
module JA4;

export {
  redef record Info += {
    # The connection uid which this fingerprint represents
    uid: string &log &optional;

    # The client hello fingerprint
    ja4: string &log &default="";

    # The client hello fingerprint with the client offered ordering
    o: string &log &default="";

    # The client hello fingerprint with the raw array output
    r: string &log &default="";

    # The client hello fingerprint with both the raw array output and with the client offered ordering
    ro: string &log &default="";

    # A hash value representing the distribution of GREASE values
    grease_hash: string &log &optional;

    # If this context is ready to be logged
    done: bool &default=F;
  };

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_ja4: event(rec: Info);
  global log_policy: Log::PolicyHook;
}

# Create the log stream and file
event zeek_init() &priority=5 {
  # Fingerprint strings are logged to a new file instead of appended to ssl.log
  Log::create_stream(JA4::LOG,
    [$columns=JA4::Info, $ev=log_ja4, $path="ja4", $policy=log_policy]
  );
}

# Make the JA4_a string
function make_a(c: connection): string {
  local proto: string = "0";
  if (c$conn$proto == tcp) {
    proto = "t";
  } else if (c$conn$proto == udp) {
    proto = "u";
  } else if ("dtls" in c$service) {
    proto = "d";
  } else if ("gquic" in c$service || "quic" in c$service) {
    proto = "q";
  }

  # 0 - No SNI
  # i - an SNI equal to the destination IP address
  # d - neither of the above
  local sni: string = "0";
  if (c$ja4$client_hello?$sni && |c$ja4$client_hello$sni| > 0) {
    sni = "i";
    # This doesn't actually validate that the SNI valid is a domain name.
    #  Doing that would require checking that the string has a valid TLD, a valid number of 
    #  subdomains, only valid characters, and likely other checks too.
    #  Consider the example SNI value of "foo.localhost", it's not a real domain but is also not an IP address
    if (c$ja4$client_hello$sni[0] != fmt("%s", c$id$resp_h)) {
      sni = "d";
    }
  }

  local alpn: string = "00";
  if (c$ja4$client_hello?$alpns && |c$ja4$client_hello$alpns| > 0) {
    alpn = c$ja4$client_hello$alpns[0][0] + c$ja4$client_hello$alpns[0][-1];
  }

  local cs_count = "00";
  if (|c$ja4$client_hello$cipher_suites| > 99) {
    cs_count = cat(99);
  } else {
    cs_count = fmt("%02d", |c$ja4$client_hello$cipher_suites|);
  }

  local ec_count = "00";
  if (|c$ja4$client_hello$extension_codes| > 99) {
    ec_count = cat(99);
  } else {
    ec_count = fmt("%02d", |c$ja4$client_hello$extension_codes|);
  }

  local version: string = "??";
  if (c$ja4$client_hello$version in TLS_VERSION_MAPPER) {
    version = TLS_VERSION_MAPPER[c$ja4$client_hello$version];
  }

  local a: string = "";  
  a = proto;
  a += version;
  a += sni;
  a += cs_count;
  a += ec_count;
  a += alpn;
  return a;
}

# Format a vector of count type to a string type
function vector_of_count_to_str(input: vector of count, format_str: string &default="%04x", dlimit: string &default=","): string {
  local output: string = "";
  for (idx, val in input) {
    output += fmt(format_str, val);
    if (idx < |input|-1) {
      output += dlimit;
    }
  }
  return output;
}

# Sort a vector of count by the count values
function order_them(input: vector of count): vector of count {
  local ordering: vector of count = order(input);
  local output: vector of count = vector();
  for (idx, val in ordering) {
    output += input[val];
  }
  return output;
}

# Produce the JA4_b hash value
function b_hash(input: vector of count): string {
  local sha256_object = sha256_hash_init();
  sha256_hash_update(sha256_object, vector_of_count_to_str(input));
  return sha256_hash_finish(sha256_object)[:12];
}

# Produce the JA4_c hash value
function c_hash(input: string): string {
  local sha256_object = sha256_hash_init();
  sha256_hash_update(sha256_object, input);
  return sha256_hash_finish(sha256_object)[:12];
}

function grease_vec_to_hash_str(grease_dist: table[count] of count): string {
  local s: string = "";
  local counts: vector of count = vector();
  for (val, cnt in grease_dist) {
    counts += cnt;
  }
  local counts_ordered = order_them(counts);
  for (idx, cnt in counts_ordered) {
    s += fmt("%s,", cnt);
  }
  # c_hash returns a truncated hash of the string
  return c_hash(s);
}

# Just before the connection's state is flushed from the sensor's memory...
#  Conduct operations on ClientHello record in c$ja4 to create JA4 record as c$ja4
# TODO - consider relocating this logic to another event, such as ssl_client_hello
event connection_state_remove(c: connection) {
  if (!c?$ja4 || !c$ja4?$client_hello || !c$ja4$client_hello?$version) { return; }

  c$ja4$uid = c$uid;
  c$ja4$grease_hash = grease_vec_to_hash_str(c$ja4$client_hello$grease_dist);

  local ja4_a: string = JA4::make_a(c);
  local ja4_b: vector of count = c$ja4$client_hello$cipher_suites;

  local extensions: vector of count = vector();
  for (idx, code in c$ja4$client_hello$extension_codes) {
    if (code == SSL::SSL_EXTENSION_SERVER_NAME || code == SSL::SSL_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
      next;
    }
    extensions += code;
  }

  local ja4_c: string = vector_of_count_to_str(order_them(extensions));
  ja4_c += delimiter;
  ja4_c += vector_of_count_to_str(c$ja4$client_hello$signature_algos);

  # ja4, ja4, ja4, ja4, ja4, ja4. say it some more. ja4, ja4, ja4.
  c$ja4$ja4 = ja4_a;
  c$ja4$ja4 += delimiter;
  c$ja4$ja4 += b_hash(order_them(ja4_b));
  c$ja4$ja4 += delimiter;
  c$ja4$ja4 += c_hash(ja4_c);

  # ja4_r
  c$ja4$r = ja4_a;
  c$ja4$r += delimiter;
  c$ja4$r += vector_of_count_to_str(order_them(ja4_b));
  c$ja4$r += delimiter;
  c$ja4$r += ja4_c;

  # original extensions ordering
  ja4_c = vector_of_count_to_str(extensions);
  ja4_c += delimiter;
  ja4_c += vector_of_count_to_str(c$ja4$client_hello$signature_algos);

  # ja4_o
  c$ja4$o = ja4_a;
  c$ja4$o += delimiter;
  c$ja4$o += b_hash(ja4_b);
  c$ja4$o += delimiter;
  c$ja4$o += c_hash(ja4_c);

  # ja4_ro
  c$ja4$ro = ja4_a;
  c$ja4$ro += delimiter;
  c$ja4$ro += vector_of_count_to_str(ja4_b);
  c$ja4$ro += delimiter;
  c$ja4$ro += ja4_c;

  # fingerprinting is marked as done and it is logged
  c$ja4$done = T;
  Log::write(JA4::LOG, c$ja4);
}

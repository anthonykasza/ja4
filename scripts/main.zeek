# Using the ClientHello context, calculate fingerprint values and log

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

	# set the JA4 values for a connection
	global set_ja4: function(c: connection);

	# Logging boilerplate
	redef enum Log::ID += { LOG };
	global log_ja4: event(rec: Info);
	global log_policy: Log::PolicyHook;
}

# Create the log stream and file
event zeek_init() &priority=5
	{
	Log::create_stream(JA4::LOG, [ $columns=JA4::Info, $ev=log_ja4, $path="ja4",
	    $policy=log_policy ]);
	}

# Make the JA4_a string
function make_a(c: connection): string
	{
	# one character representing the protocol where from the Hello originated
	local proto: string = "0";
	local trans_proto = get_port_transport_proto(c$id$resp_p);
	if ( "QUIC" in c$service )
		{
		proto = "q";
		}
	else if ( "DTLS" in c$service )
		{
		proto = "d";
		}
	else if ( "RDP" in c$service )
		{
		proto = "r";
		}
	else if ( "RDPEUDP" in c$service )
		{
		proto = "e";
		}
	else if ( trans_proto == tcp )
		{
		proto = "t";
		}
	else if ( trans_proto == udp )
		{
		proto = "u";
		}

	# 0 - No SNI
	# i - an SNI equal to the destination IP address
	# d - neither of the above
	local sni: string = "0";
	if ( c$ja4$client_hello?$sni && |c$ja4$client_hello$sni| > 0 )
		{
		sni = "i";
		# This doesn't actually validate that the SNI valid is a domain name.
		#  Doing that would require checking that the string has a valid TLD, a valid number of
		#  subdomains, only valid characters, and likely other checks too.
		#  Consider the example SNI value of "foo.localhost", it's not a real domain but is also not an IP address
                #
                # Also consider the example where the SNI value is "8.8.8.8" but the responding host is using "1.1.1.1".
                #  In this case, the SNI is indeed an IP address, but we still set the value to "d"
                #  because the SNI doesn't match the destination IPv4.
                #
                # Also, consider the example where the SNI is an IPv6 address.
                #  If the format of the IPv6 in the SNI differs from how 
                #  Zeek would format the IPv6 address as a string, then this sets the value to "d".
                #
                # TODO: I feel like there are potential evasions due to the ambiguity of this value.
                #       Ask for more clarity from the techspec
		if ( c$ja4$client_hello$sni[0] != fmt("%s", c$id$resp_h) )
			{
			sni = "d";
			}
		}

	local alpn: string = "00";
	if ( c$ja4$client_hello?$alpns && |c$ja4$client_hello$alpns| > 0 )
		{
		alpn = c$ja4$client_hello$alpns[0][0] + c$ja4$client_hello$alpns[0][-1];
		}

	local cs_count = "00";
	if ( |c$ja4$client_hello$cipher_suites| > 99 )
		{
		cs_count = cat(99);
		}
	else
		{
		cs_count = fmt("%02d", |c$ja4$client_hello$cipher_suites|);
		}

	local ec_count = "00";
	if ( |c$ja4$client_hello$extension_codes| > 99 )
		{
		ec_count = cat(99);
		}
	else
		{
		ec_count = fmt("%02d", |c$ja4$client_hello$extension_codes|);
		}

	local version = TLS_VERSION_MAPPER[c$ja4$client_hello$version];

	local a: string = "";
	a += proto;
	a += version;
	a += sni;
	a += cs_count;
	a += ec_count;
	a += alpn;
	return a;
	}

# Format a vector of count type to a string type
function vector_of_count_to_str(input: vector of count, format_str: string
    &default="%04x", dlimit: string &default=","): string
	{
	local output: string = "";
	for ( idx in input )
		{
		local val = input[idx];
		output += fmt(format_str, val);
		if ( idx < |input| - 1 )
			{
			output += dlimit;
			}
		}
	return output;
	}

# Sort a vector of count by the count values
function order_them(input: vector of count): vector of count
	{
	local ordering: vector of count = order(input);
	local output: vector of count = vector();
	for ( idx in ordering )
		{
		local val = ordering[idx];
		output += input[val];
		}
	return output;
	}

# truncated sha256 or all zeros for empty string
function trunc_sha256(input: string, hash_trunc_len: count
    &default=JA4::hash_trunc_len): string
	{
	if ( |input| == 0 )
		{
		local empty: string = "";
		local cnt: count = hash_trunc_len;
		while ( cnt > 0 )
			{
			empty += "0";
			cnt -= 1;
			}
		return empty;
		}
	local sha256_object = sha256_hash_init();
	sha256_hash_update(sha256_object, input);
	return sha256_hash_finish(sha256_object)[:hash_trunc_len];
	}

# turn the grease_dist table into a string, then trunc_hash it
function grease_table_to_hash(grease_dist: table[count] of count): string
	{
	local counts: vector of count = vector();
	local cnt: count;
	for ( val, cnt in grease_dist )
		{
		counts += cnt;
		}
	local counts_ordered = order_them(counts);
	local s: string = "";
	for ( idx in counts_ordered )
		{
		cnt = counts_ordered[idx];
		s += fmt("%s,", cnt);
		}
	return trunc_sha256(s);
	}

# set the fingerprint fields of the Info record
function set_ja4(c: connection)
	{
	c$ja4$uid = c$uid;
	c$ja4$grease_hash = grease_table_to_hash(c$ja4$client_hello$grease_dist);

	local ja4_a: string = JA4::make_a(c);
	local ja4_b: vector of count = c$ja4$client_hello$cipher_suites;

	local extensions: vector of count = vector();
	for ( idx in c$ja4$client_hello$extension_codes )
		{
		local code = c$ja4$client_hello$extension_codes[idx];
		if ( code == SSL::SSL_EXTENSION_SERVER_NAME
		    || code == SSL::SSL_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION )
			{
			next;
			}
		extensions += code;
		}
	local ja4_c: string = vector_of_count_to_str(order_them(extensions));
	ja4_c += delimiter;
	ja4_c += vector_of_count_to_str(c$ja4$client_hello$signature_algos);

	# ja4
	c$ja4$ja4 = ja4_a;
	c$ja4$ja4 += delimiter;
	c$ja4$ja4 += trunc_sha256(vector_of_count_to_str(order_them(ja4_b)));
	c$ja4$ja4 += delimiter;
	c$ja4$ja4 += trunc_sha256(ja4_c);

	# ja4_r
	c$ja4$r = ja4_a;
	c$ja4$r += delimiter;
	c$ja4$r += vector_of_count_to_str(order_them(ja4_b));
	c$ja4$r += delimiter;
	c$ja4$r += ja4_c;

	# original extensions and signature algos ordering
	ja4_c = vector_of_count_to_str(extensions);
	ja4_c += delimiter;
	ja4_c += vector_of_count_to_str(c$ja4$client_hello$signature_algos);

	# ja4_o
	c$ja4$o = ja4_a;
	c$ja4$o += delimiter;
	c$ja4$o += trunc_sha256(vector_of_count_to_str(( ja4_b )));
	c$ja4$o += delimiter;
	c$ja4$o += trunc_sha256(ja4_c);

	# ja4_ro
	c$ja4$ro = ja4_a;
	c$ja4$ro += delimiter;
	c$ja4$ro += vector_of_count_to_str(ja4_b);
	c$ja4$ro += delimiter;
	c$ja4$ro += ja4_c;

	c$ja4$done = T;
	}

# Upon expiry of the connection: do the math, log the strings
event connection_state_remove(c: connection)
	{
	if ( ! c?$ja4 || ! c$ja4?$client_hello || ! c$ja4$client_hello?$version )
		{
		return;
		}

	set_ja4(c);
	Log::write(JA4::LOG, c$ja4);
	}

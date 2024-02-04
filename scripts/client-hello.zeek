# Fill out a ClientHello context as Zeek parses the message

module JA4;

export {
	type ClientHello: record {
		# The highest TLS version found in the supported versions extension or the TLS record
		version: count &optional;

		# The cipher suites offered by the client, GREASE removed
		cipher_suites: vector of count &default=vector();

		# The compression methods offered by the client, GREASE removed
		compression_methods: vector of count &default=vector();

		# The extensions present in the ClientHello, GREASE removed
		extension_codes: vector of count &default=vector();

		# The alpn values present in the ClientHello
		alpns: vector of string &optional;

		# The signature and hashing algorithms offered by the client
		signature_algos: vector of count &default=vector();

		# The sni values present in the ClientHello
		sni: vector of string &optional;

		# GREASE value counts from various fields
		grease_dist: table[count] of count &default=table();
	};
}

redef record Info += {
	client_hello: ClientHello &default=[ ];
};

# Format the signature and hashing algorithm codes into a single value
function make_dword(byte1: count, byte2: count): count
	{
	local t: table[string] of count = [ [ "0" ] = 0, [ "1" ] = 1, [ "2" ] = 2, [ "3" ] =
	    3, [ "4" ] = 4, [ "5" ] = 5, [ "6" ] = 6, [ "7" ] = 7, [ "8" ] =
	    8, [ "9" ] = 9, [ "a" ] = 10, [ "b" ] = 11, [ "c" ] = 12, [ "d" ] =
	    13, [ "e" ] = 14, [ "f" ] = 15 ];
	local b1 = to_lower(fmt("%02x", byte1));
	local b2 = to_lower(fmt("%02x", byte2));
	local byte1_total: count = ( t[b1[0]] * 16 * 16 * 16 ) + ( t[b1[1]] * 16 * 16 );
	local byte2_total: count = ( t[b2[0]] * 16 ) + ( t[b2[1]] * 1 );
	return byte1_total + byte2_total;
	}

function add_to_grease_dist(c: connection, val: count)
	{
	if ( val in c$ja4$client_hello$grease_dist )
		{
		c$ja4$client_hello$grease_dist[val] += 1;
		}
	else
		{
		c$ja4$client_hello$grease_dist[val] = 1;
		}
	}

# This event is processed at the end of the hello, after all the extension-specific events occur
event ssl_client_hello(c: connection, version: count, record_version: count,
    possible_ts: time, client_random: string, session_id: string,
    ciphers: index_vec, comp_methods: index_vec)
	{
	if ( ! c?$ja4 )
		{
		c$ja4 = [ ];
		}
	local val: count;

	local no_grease_ciphers: index_vec = vector();
	for ( idx in ciphers )
		{
		val = ciphers[idx];
		if ( val !in TLS_GREASE_TYPES )
			{
			no_grease_ciphers += val;
			}
		else
			{
			add_to_grease_dist(c, val);
			}
		}

	local no_grease_comp_methods: index_vec = vector();
	for ( idx in comp_methods )
		{
		val = comp_methods[idx];
		if ( val !in TLS_GREASE_TYPES )
			{
			no_grease_comp_methods += val;
			}
		else
			{
			add_to_grease_dist(c, val);
			}
		}

	if ( ! c$ja4$client_hello?$version )
		{
		# use the larger
		c$ja4$client_hello$version = version > record_version ? version :
		    record_version;
		}

	c$ja4$client_hello$cipher_suites = no_grease_ciphers;
	c$ja4$client_hello$compression_methods = no_grease_comp_methods;
	}

# For each extension, ignoring GREASE, build up an array of code in the order they appear
event ssl_extension(c: connection, is_client: bool, code: count, val: string)
	{
	if ( ! is_client )
		{
		return;
		}
	if ( ! c?$ja4 )
		{
		c$ja4 = [ ];
		}
	if ( code in TLS_GREASE_TYPES )
		{
		add_to_grease_dist(c, code);
		return;
		}
	else
		{
		if ( ! c$ja4?$client_hello )
			{
			c$ja4$client_hello = [ ];
			}
		c$ja4$client_hello$extension_codes += code;
		}
	}

# For each alpn build up an array protocol strings
event ssl_extension_application_layer_protocol_negotiation(c: connection,
    is_client: bool, protocols: string_vec)
	{
	if ( ! is_client )
		{
		return;
		}
	if ( ! c?$ja4 )
		{
		c$ja4 = [ ];
		}
	if ( ! c$ja4$client_hello?$alpns )
		{
		c$ja4$client_hello$alpns = vector();
		}
	c$ja4$client_hello$alpns += protocols;
	}

# If the supported versions extension is present, find the largest offered version and store it
event ssl_extension_supported_versions(c: connection, is_client: bool,
    versions: index_vec)
	{
	if ( ! is_client )
		{
		return;
		}
	if ( ! c?$ja4 )
		{
		c$ja4 = [ ];
		}
	local val: count;
	local largest: count = 0;
	for ( idx in versions )
		{
		val = versions[idx];
		if ( val in TLS_GREASE_TYPES )
			{
			add_to_grease_dist(c, val);
			next;
			}
		if ( val > largest )
			{
			largest = val;
			}
		}
	if ( ! c$ja4$client_hello?$version )
		{
		c$ja4$client_hello$version = largest;
		}
	else
		{
		c$ja4$client_hello$version = largest > c$ja4$client_hello$version ? largest :
		    c$ja4$client_hello$version;
		}
	}

# Build up a list of hash and signature algorithms in the order they appear
event ssl_extension_signature_algorithm(c: connection, is_client: bool,
    signature_algorithms: signature_and_hashalgorithm_vec)
	{
	if ( ! is_client )
		{
		return;
		}
	if ( ! c?$ja4 )
		{
		c$ja4 = [ ];
		}
	for ( idx in signature_algorithms )
		{
		local val = signature_algorithms[idx];
		local ha: count = val$HashAlgorithm;
		local sa: count = val$SignatureAlgorithm;
		c$ja4$client_hello$signature_algos += make_dword(ha, sa);
		}
	}

# Store the array of SNIs in the connection context
event ssl_extension_server_name(c: connection, is_client: bool,
    names: string_vec)
	{
	if ( ! is_client )
		{
		return;
		}
	if ( ! c?$ja4 )
		{
		c$ja4 = [ ];
		}
	c$ja4$client_hello$sni = names;
	}

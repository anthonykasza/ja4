# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: cat ja4.log | zeek-cut ja4 o r ro grease_hash > ja4.filtered
# @TEST-EXEC: btest-diff ja4.filtered
# @TEST-EXEC: btest-diff output

event my_finalize_ssl(dummy: connection)
	{
	hook SSL::finalize_ssl(dummy);
	}

event zeek_init()
	{
	local dummy: connection = [ $uid="UUIIDD", $start_time=network_time(),
	    $id=[ $orig_h=1.1.1.1, $orig_p=1/tcp, $resp_h=2.2.2.2,
	    $resp_p=2/tcp ], $orig=[ $size=0, $state=0, $flow_label=0 ],
	    $resp=[ $size=0, $state=0, $flow_label=0 ], $duration=0msec,
	    $service=set("SSL"), $history="" ];

	event ssl_extension(dummy, T, 6682, "");
	event ssl_extension(dummy, T, 65281, "\x00");
	event ssl_extension_server_name(dummy, T, vector("ritter.vg"));
	event ssl_extension(dummy, T, 0, "\x00\x0c\x00\x00\x09ritter.vg");
	event ssl_extension(dummy, T, 23, "");
	event ssl_extension(dummy, T, 35, "");
	event ssl_extension_signature_algorithm(dummy, T, vector([ $HashAlgorithm=4,
	    $SignatureAlgorithm=3 ], [ $HashAlgorithm=8, $SignatureAlgorithm=4
	    ], [ $HashAlgorithm=4, $SignatureAlgorithm=1 ], [ $HashAlgorithm=5,
	    $SignatureAlgorithm=3 ], [ $HashAlgorithm=8, $SignatureAlgorithm=5
	    ], [ $HashAlgorithm=5, $SignatureAlgorithm=1 ], [ $HashAlgorithm=8,
	    $SignatureAlgorithm=6 ], [ $HashAlgorithm=6, $SignatureAlgorithm=1
	    ], [ $HashAlgorithm=2, $SignatureAlgorithm=1 ]));
	event ssl_extension(dummy, T, 13, "\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01");
	event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
	event ssl_extension(dummy, T, 18, "");
	event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector(
	    "h2", "http/1.1"));
	event ssl_extension(dummy, T, 16, "\x00\x0c\x02h2\x08http/1.1");
	event ssl_extension(dummy, T, 30032, "");
	event ssl_extension(dummy, T, 11, "\x01\x00");
	event ssl_extension_key_share(dummy, T, vector(14906, 29));
	event ssl_extension(dummy, T, 40, "\x00)::\x00\x01\x00\x00\x1d\x00 \xef}\xd6\xca S\x1c\xa7\xc7[\xdcF\x91\xa7\xbe\x9e\xeb\x89PE\xccG\x10\x1c]FH*:D\xf3\x07");
	event ssl_extension_psk_key_exchange_modes(dummy, T, vector(1));
	event ssl_extension(dummy, T, 45, "\x01\x01");
	event ssl_extension_supported_versions(dummy, T, vector(43690, 32530, 771, 770,
	    769));
	event ssl_extension(dummy, T, 43,
	    "\x0a\xaa\xaa\x7f\x12\x03\x03\x03\x02\x03\x01");
	event ssl_extension(dummy, T, 10, "\x00\x08::\x00\x1d\x00\x17\x00\x18");
	event ssl_extension(dummy, T, 24, "\x00\x0a\x01\x02");
	event ssl_extension(dummy, T, 35466, "\x00");
	event ssl_extension(dummy, T, 21, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
	event ssl_client_hello(dummy, 771, 769, network_time(),
	    "\xa7\xc0QZ'<\xb8\xf1)\x01\x11\x16\xa3V\x0e\x06g#$\xfdu:3v?\xa0\xa9%", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	    vector(19018, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393,
	    52392, 52244, 52243, 49171, 49172, 156, 157, 47, 53, 10), vector(0));
	event my_finalize_ssl(dummy);
	}

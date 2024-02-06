# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: cat ja4.log | zeek-cut ja4 o r ro grease_hash > ja4.filtered
# @TEST-EXEC: btest-diff ja4.filtered
# @TEST-EXEC: btest-diff output

event zeek_done()
	{
	local dummy: connection = [ $id=[ $orig_h=1.1.1.1, $orig_p=1/tcp,
	    $resp_h=2.2.2.2, $resp_p=2/tcp ], $orig=[ $size=0, $state=0,
	    $flow_label=0 ], $resp=[ $size=0, $state=0, $flow_label=0 ],
	    $start_time=network_time(), $duration=0msec, $service=set("SSL"),
	    $history="", $uid="UUIIDD" ];

	local ch: JA4::ClientHello = [ $version=0x0304, $cipher_suites=vector(0x1a1a,
	    0x1111, 0x1000, 0x1001, 0x1002), $compression_methods=vector(0x2a2a,
	    0x2222, 0x2000, 0x2001, 0x2002, 0x2003), $extension_codes=vector(
	    0x3a3a, 0x3333, 0x3000, 0x3001, 0x3002, 0x3003, 0x3004, 0x3005,
	    0x3006, 0x3007), $alpns=vector("ZZ", "00"), $signature_algos=vector(
	    0x4444, 0x5555, 0x6666, 0x7777, 0x8888, 0x9999), $sni=vector(
	    "foo.localhost", "TwoSNIs?"), $grease_dist=table([ 0x0a0a ] = 1) ];

	dummy$ja4 = [ ];
	dummy$ja4$client_hello = ch;
	JA4::set_ja4(dummy);
	Log::write(JA4::LOG, dummy$ja4);
	}

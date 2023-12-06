# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: cat ja4.log | zeek-cut ja4 o r ro grease_hash > ja4.filtered
# @TEST-EXEC: btest-diff ja4.filtered
# @TEST-EXEC: btest-diff output

event zeek_done()
	{
	local dummy: connection = [ $id=[ $orig_h=1.1.1.1, $orig_p=1/tcp,
	    $resp_h=2.2.2.2, $resp_p=2/udp ], $orig=[ $size=0, $state=0,
	    $flow_label=0 ], $resp=[ $size=0, $state=0, $flow_label=0 ],
	    $start_time=network_time(), $duration=0msec, $service=set("QUIC"),
	    $history="", $uid="UUIIDD" ];

	local ch: JA4::ClientHello = [ $version=0x0303, $cipher_suites=vector(0x1111),
	    $compression_methods=vector(0x2222), $extension_codes=vector(
	    0x3333), $alpns=vector("ZZ", "00"), $signature_algos=vector(0x4444,
	    0x5555), $sni=vector("2.2.2.2"), $grease_dist=table([ 0x0000 ] = 0) ];

	dummy$ja4 = [ ];
	dummy$ja4$client_hello = ch;
	JA4::set_ja4(dummy);
	Log::write(JA4::LOG, dummy$ja4);
	}

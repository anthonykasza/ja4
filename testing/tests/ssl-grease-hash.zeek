# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: cat ja4.log | zeek-cut ja4 o r ro grease_hash > ja4.filtered
# @TEST-EXEC: btest-diff ja4.filtered
# @TEST-EXEC: btest-diff output

event zeek_done() {
  local dummy: connection = [ 
    $uid="UUIIDD",
    $start_time=network_time(),
    $id=[
      $orig_h=1.1.1.1, $orig_p=1/tcp,
      $resp_h=2.2.2.2, $resp_p=2/tcp
    ],
    $orig=[$size=0, $state=0, $flow_label=0],
    $resp=[$size=0, $state=0, $flow_label=0],
    $duration=0msec,
    $service=set("SSL"),
    $history=""
  ];

  local ch1: JA4::ClientHello = [
    $version=0xffff,
    $cipher_suites=vector(0x1a1a, 0x1111),
    $compression_methods=vector(0x2a2a, 0x2222),
    $extension_codes=vector(0x3a3a, 0x3333), 
    $alpns=(vector() as vector of string),
    $signature_algos=vector(0x4444),
    $sni=(vector() as vector of string),
    $grease_dist=table([0xa0a0] = 3)
  ];

  local ch2: JA4::ClientHello = [
    $version=0xffff,
    $cipher_suites=vector(0x1a1a, 0x1111),
    $compression_methods=vector(0x2a2a, 0x2222),
    $extension_codes=vector(0x3a3a, 0x3333), 
    $alpns=(vector() as vector of string),
    $signature_algos=vector(0x4444),
    $sni=(vector() as vector of string),
    $grease_dist=table([0xafaf] = 3)
  ];

  dummy$ja4 = [];

  dummy$ja4$client_hello = ch1;
  JA4::set_ja4(dummy);
  Log::write(JA4::LOG, dummy$ja4);

  dummy$ja4$client_hello = ch2;
  JA4::set_ja4(dummy);
  Log::write(JA4::LOG, dummy$ja4);
}

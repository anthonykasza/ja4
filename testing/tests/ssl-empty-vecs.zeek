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

  local empty_table: table[count] of count = table();
  local ch: JA4::ClientHello = [
    $version=0xffff,
    $cipher_suites=(vector() as vector of count),
    $compression_methods=(vector() as vector of count),
    $extension_codes=(vector() as vector of count),
    $alpns=(vector() as vector of string),
    $signature_algos=(vector() as vector of count),
    $sni=(vector() as vector of string),
    $grease_dist=empty_table
  ];

  dummy$ja4 = [];
  dummy$ja4$client_hello = ch;
  JA4::set_ja4(dummy);
  Log::write(JA4::LOG, dummy$ja4);
}

# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: cat ja4.log | zeek-cut ja4 o r ro grease_hash > ja4.filtered
# @TEST-EXEC: btest-diff ja4.filtered
# @TEST-EXEC: btest-diff output

event my_finalize_ssl(dummy: connection) {
  hook SSL::finalize_ssl(dummy);
}

event zeek_init() {
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

  event ssl_extension(dummy, T, 10, "\x00\x06\x00\x17\x00\x18\x00\x19");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=3]));
  event ssl_extension(dummy, T, 13, "\x00\x0a\x05\x01\x04\x01\x02\x01\x04\x03\x02\x03");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xfdW.\x14B(\xc3\xfd\"\x08\xe9\xde\xa6\xe2\xb3\xd2\xb8\xa8\x997)\xea\xfcN\xccx\x91\xe0", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(255, 49188, 49187, 49162, 49161, 49160, 49192, 49191, 49172, 49171, 49170, 49190, 49189, 49157, 49156, 49155, 49194, 49193, 49167, 49166, 49165, 107, 103, 57, 51, 22, 61, 60, 53, 47, 10, 49159, 49169, 49154, 49164, 5, 4, 175, 174, 141, 140, 138, 139), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x03\x00\x01\x02");
}

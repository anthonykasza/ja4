# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: cat ja4.log | zeek-cut ja4 o r ro grease_hash > ja4.filtered
# @TEST-EXEC: btest-diff ja4.filtered
# @TEST-EXEC: btest-diff output

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

  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension(dummy, T, 10, "\x002\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x02\x02");
  event ssl_extension(dummy, T, 15, "\x01");
  event ssl_client_hello(dummy, 771, 771, network_time(), "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(4, 5, 10, 13, 16, 19, 22, 47, 48, 49, 50, 51, 53, 54, 55, 56, 57, 60, 61, 62, 63, 64, 65, 68, 69, 102, 103, 104, 105, 106, 107, 132, 135, 136, 150, 156, 157, 158, 159, 255, 49154, 49155, 49156, 49157, 49159, 49160, 49161, 49162, 49164, 49165, 49166, 49167, 49169, 49170, 49171, 49172, 49187, 49188, 49191, 49195, 49196, 49199, 49201, 49202), vector(0));
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, F, 15, "\x01");
  event connection_state_remove(dummy);
}

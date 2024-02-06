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

  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x00\x06\x00\x15\x00\x17\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x1c\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01");
  event ssl_extension_supported_versions(dummy, T, vector(772));
  event ssl_extension(dummy, T, 43, "\x02\x03\x04");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension(dummy, T, 51, "\x00=\x00\x15\x009\x04t+\xee\xe2\xf4\x0dq\xfd}\xe4B\xc4\x82\x94P\xb0\x81\"U\x14\xe2,]\x87\xb4\x7f\xc5\x95\x8b\xcc\xc7\xffi\x83]w1\x16kb\xe9-\xe5\x16\xb8\xaf\x90\xfeE\xcb\xb0V\xce6O@");
  event ssl_client_hello(dummy, 771, 769, network_time(), "7\xd4\xf5\x98\xa7\x0dij\x91r\xb2\x96\xc9hR\xc9\xda\xe4\xa3\xc9\xcakI\xd2\x02\x16h\xa1", "\x1ak\xb86\x8a\xdd\x0e(\x01[\xd6\xcc\xedd\x826\xf4\x9e$\x07\xf1\x96S\xac\x1f\xdd\x1f\xfaH\xbf\xae\xcd", vector(4866, 4867, 4865, 255), vector(0));
  event ssl_extension_supported_versions(dummy, F, vector(772));
  event ssl_extension(dummy, F, 43, "\x03\x04");
  event ssl_extension(dummy, F, 51, "\x00\x17");
  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x00\x06\x00\x15\x00\x17\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x1c\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01");
  event ssl_extension_supported_versions(dummy, T, vector(772));
  event ssl_extension(dummy, T, 43, "\x02\x03\x04");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension(dummy, T, 51, "\x00E\x00\x17\x00A\x04w\x07\x06\xeb\xa5\xd9\x06\"\xe4\x11Z(C\xaf\xeb\xa4\xb1\xf4\xed\x9b9\xeb\x09\x93\x98X\x0dN\xe2!\xf8\x1dyM\xc5i\xec\xc7\xd7:'\xbe\xbd$I\x04##J\xa1S\xcb\x87\x0d\xbd,\xe5\xa7X>l\xbc=\x01");
  event ssl_client_hello(dummy, 771, 771, network_time(), "7\xd4\xf5\x98\xa7\x0dij\x91r\xb2\x96\xc9hR\xc9\xda\xe4\xa3\xc9\xcakI\xd2\x02\x16h\xa1", "\x1ak\xb86\x8a\xdd\x0e(\x01[\xd6\xcc\xedd\x826\xf4\x9e$\x07\xf1\x96S\xac\x1f\xdd\x1f\xfaH\xbf\xae\xcd", vector(4866, 4867, 4865, 255), vector(0));
  event ssl_extension(dummy, F, 51, "\x00\x17\x00A\x04e\xfeR\xa1\x96\x86\xb5\xdd\x1d\xe1\x0cV\xf3\x80\x94\xae\x84.\xf6\x0fQ\x11\xec\x0e\x0e\xe1}9.T\xecB\x16H\x9bn\xcbb,\\x88M\x90&\xe2JB\x99\x0cDY\xf2)\xcc\xee\x0d0\xdf\xc2\xa3g\xf9c\xd8");
  event ssl_extension_supported_versions(dummy, F, vector(772));
  event ssl_extension(dummy, F, 43, "\x03\x04");
  event connection_state_remove(dummy);
}

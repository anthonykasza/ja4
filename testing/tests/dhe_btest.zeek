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

  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=2], [$HashAlgorithm=2, $SignatureAlgorithm=3]));
  event ssl_extension(dummy, T, 13, "\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03");
  event ssl_extension(dummy, T, 15, "\x01");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\x1f\x7f\x8a\xe4\xd8\xddE\xf3\x1e\xd2\xe1X\xf5\xf9\xeegk|\xb2\xc9%\x85\xd8\xa3\xe1\xc2\xda~", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(136, 255), vector(1, 0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension(dummy, F, 15, "\x01");
}

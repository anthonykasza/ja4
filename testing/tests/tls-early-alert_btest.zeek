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

  event ssl_extension_server_name(dummy, T, vector("jeffbryner.com"));
  event ssl_extension(dummy, T, 0, "\x00\x11\x00\x00\x0ejeffbryner.com");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension(dummy, T, 10, "\x00\x06\x00\x17\x00\x18\x00\x19");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 13172, "");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("h2", "spdy/3.1", "http/1.1"));
  event ssl_extension(dummy, T, 16, "\x00\x15\x02h2\x08spdy/3.1\x08http/1.1");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=2, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00\x14\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x04\x02\x02\x02");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xbd\xc1P\x1e\xb4\xfa\x8d\xa6\x9a\x90\xf7\x0ff\x92A\xc83:\x17\xe9\xa9\x9b\xeeh\x0cR.\xb1", "M\x1f\xe6\xda\x01\xecw)\xaf \xaaE\x8fG\xb1>\xc8J\x1a\xe4pEe\xfb\x13\x19k\xbf\xe6\xf0\xd2\x87", vector(49195, 49199, 49162, 49161, 49171, 49172, 51, 57, 47, 53, 10), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 0, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, F, 35, "");
}

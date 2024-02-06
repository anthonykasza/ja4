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

  event ssl_extension_server_name(dummy, T, vector("google.de"));
  event ssl_extension(dummy, T, 0, "\x00\x0c\x00\x00\x09google.de");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension(dummy, T, 10, "\x00\x06\x00\x17\x00\x18\x00\x19");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 13172, "");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("spdy/3", "spdy/3.1", "http/1.1"));
  event ssl_extension(dummy, T, 16, "\x00\x19\x06spdy/3\x08spdy/3.1\x08http/1.1");
  event ssl_extension(dummy, T, 30032, "");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=2, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02");
  event ssl_extension(dummy, T, 18, "");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xccTd\xd4;\x10F\xf6\x88%\xac\xf4m\x92f2\x89\xd2\xf9\x05\xec\xfah~\x85j\xff\xaa", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49195, 49199, 158, 52244, 52243, 49162, 49161, 49171, 49172, 49159, 49169, 51, 50, 57, 156, 47, 53, 10, 5, 4), vector(0));
  event ssl_extension(dummy, F, 0, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension(dummy, F, 30032, "");
  event ssl_extension_application_layer_protocol_negotiation(dummy, F, vector("spdy/3.1"));
  event ssl_extension(dummy, F, 16, "\x00\x09\x08spdy/3.1");
  event connection_state_remove(dummy);
}

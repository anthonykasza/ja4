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

  event ssl_extension_server_name(dummy, T, vector("heise.de"));
  event ssl_extension(dummy, T, 0, "\x00\x0b\x00\x00\x08heise.de");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension(dummy, T, 10, "\x00\x0c\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("h2", "http/1.1"));
  event ssl_extension(dummy, T, 16, "\x00\x0c\x02h2\x08http/1.1");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension(dummy, T, 51, "\x00i\x00\x1d\x00 p\xe4\x07\xd3\xeb\xfe\xd3\xd6B\xe6_\x0e\x91\x9b\xcd\xb6\xa6\xf7T\xfd\x8a;;\x94M\x1b\xdd\xa9u\xa1\x9ax\x00\x17\x00A\x04\x94\xbat\xb4>\x8f\xaa\xda\xc8\x03t\xb1\x00 \x83\xf9\xb9\x92\xa9\xccfnx\x82p\xf0\xea\xb2\x19\x87\x04\x15\xb6\xb1\xa9\xd1N2\xe1\xd8@\x03\xc8l\x9d\xca\xf4\xbd:\xe1\x94\xcd\xa0\x0a\xab\xc1M\x9a\xa3\xbc\xae\x1d\xf8\xe1");
  event ssl_extension_supported_versions(dummy, T, vector(772, 771));
  event ssl_extension(dummy, T, 43, "\x04\x03\x04\x03\x03");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension(dummy, T, 28, "@\x01");
  event ssl_extension(dummy, T, 21, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xb4\x0a$KH\xe4.\xac(qD\xb1\xb790W\xca\xa11\xf9a\xa7\x8e8\xb0\xe7|\x1e", "\xa7?\xd3\xe2\x96\xa0\xc4\x0fW;i\x15=\xae\xf2\xa3Z\x93\xc3\x1a\xe4\x85\xb6\xaf\x10\xb7E}-\x14\x90\xae", vector(49200), vector(0));
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 0, "");
  event ssl_extension(dummy, F, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension_application_layer_protocol_negotiation(dummy, F, vector("http/1.1"));
  event ssl_extension(dummy, F, 16, "\x00\x09\x08http/1.1");
  event ssl_extension(dummy, F, 23, "");
  event connection_state_remove(dummy);
}

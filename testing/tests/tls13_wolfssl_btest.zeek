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

  event ssl_extension(dummy, T, 51, "\x00E\x00\x17\x00A\x04\xa6d\xa5<!MK\xf1uH\xd8lm\x86\xd3d\x13\xfd-\x9b\x9f\xd3\xfe\x9e\x9e\x0a\xde\xebB$v\xcc\\x93\x99\x97\x0c\x00\x1b9\xe3;\x91\x92\x8f\x00\xf4\x96\xc9\x80\x90\xa7W\x1b\xf3\x1ej\x90\xf6q~\xfa\x90!");
  event ssl_extension_supported_versions(dummy, T, vector(772, 771, 770));
  event ssl_extension(dummy, T, 43, "\x06\x03\x04\x03\x03\x03\x02");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x1e\x06\x03\x05\x03\x04\x03\x02\x03\x08\x06\x08\x0b\x08\x05\x08\x0a\x08\x04\x08\x09\x06\x01\x05\x01\x04\x01\x03\x01\x02\x01");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension(dummy, T, 10, "\x00\x0e\x00\x19\x00\x18\x00\x17\x00\x15\x00\x13\x00\x10\x01\x00");
  event ssl_extension(dummy, T, 23, "");
  event ssl_client_hello(dummy, 771, 771, network_time(), "\x93\x98S\xf7K\xb0\x84\xd6\xf5NnE\x0b\x98\x0b\xf9j1\x19\xf4\xbd[\xc8\xab\x82\xecV ", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(4866), vector(0));
  event ssl_extension(dummy, F, 51, "\x00\x17\x00A\x04\xf6\xb5c\xa3\xba\x8eM\x9a\x94[\xcb\x83\xeb\x8b\xe2\x92\xb0G$t\x97$\xb0\xeb\xbbj\xb7&\xac\x9c\xc8*A&\x8au#&\xb1\x11\x8a\x09\x9d\x9fC\xb2p'\xf2$\xed\x1aq\x9b7b\xac\xfc\xb9?\xa2\xdc\x94a");
  event ssl_extension_supported_versions(dummy, F, vector(772));
  event ssl_extension(dummy, F, 43, "\x03\x04");
  event connection_state_remove(dummy);
}

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

  event ssl_extension(dummy, T, 51, "\x00E\x00\x17\x00A\x04\x9ff\xe7\xf5i\xe4H\x8bVb\xd6FG\xe7\x9a\\xfeo\x19\x94\xa1w\xad\xe48\xac\x12\x9c\x9e\x19\xee\xdeIT\x88/\x80 \xa59p32\xc24E\xc0\x90\xef\xca?\xb5\xb9\xdeE\x05\x94lA@\x07l\xaf\xf5");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("doq"));
  event ssl_extension(dummy, T, 16, "\x00\x04\x03doq");
  event ssl_extension_supported_versions(dummy, T, vector(772));
  event ssl_extension(dummy, T, 43, "\x02\x03\x04");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x08\x08\x04\x04\x03\x04\x01\x02\x01");
  event ssl_extension(dummy, T, 10, "\x00\x04\x00\x17\x00\x1d");
  event ssl_extension(dummy, T, 57, "\x05\x04\x80\x00\xff\xff\x04\x04\x80\x01\x00\x00\x01\x04\x80\x00N \x03\x02D\xd0\x0e\x01\x03\x0b\x01\x0a\x0f\x08\x0f\xb94w_${\x8e");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_client_hello(dummy, 771, 771, network_time(), "\xfe\x1b\x95\xc74\x83\x93i\x1bt@H\xf5\x14\xed~\xc2\x10f\xcd\xecT\\xd5^p7\xe6", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(4865, 4866, 4867), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension_supported_versions(dummy, F, vector(772));
  event ssl_extension(dummy, F, 43, "\x03\x04");
  event ssl_extension(dummy, F, 51, "\x00\x17\x00A\x04S0\x01\xb25S\x06\x1a]\xa2\xd2R\x1a\xdb'\xc5\x0c\x16\x0f\xc4`4\xa5\x1b\xd4\x98\xa0U\xd9<\xc8fyy\x03\xc4Vn\xebZ-\xcf{ntvV\xad\x0f6\x12\xde\xc1{\xa0\xbb\xbbqOD\x868K\xc4");
}

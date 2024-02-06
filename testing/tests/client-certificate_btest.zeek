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

  event ssl_extension_server_name(dummy, T, vector("certauth.idrix.fr"));
  event ssl_extension(dummy, T, 0, "\x00\x14\x00\x00\x11certauth.idrix.fr");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension(dummy, T, 10, "\x00\x0c\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("h2", "http/1.1"));
  event ssl_extension(dummy, T, 16, "\x00\x0c\x02h2\x08http/1.1");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension(dummy, T, 34, "\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03");
  event ssl_extension(dummy, T, 51, "\x00i\x00\x1d\x00 \x01\x9f\xa9iOV\x9d\x9c\xef\x1f\x989\x0b\x05\xba\x8c\x0f\xadf\x8d\x08\x82\xdc@Q\xc1\x09#P\xa2\xc48\x00\x17\x00A\x04:|\x1e\xa9q\xb4A\"p\xc8z\xed\xf5\x06\x9b8}7\xc2!\xef\xde\x0fT\x88x2\x96\xb2\x8f:\xaf\xb7\x80\x80<\x05\xe0\xa0\xcf\x9f\xa4\xfb\\x8cG\x9f\xed\xa9#rk_f\xcb\x9c\xc3\xd2q\xe1\xdc\xcb\x8b\xe8");
  event ssl_extension_supported_versions(dummy, T, vector(772, 771));
  event ssl_extension(dummy, T, 43, "\x04\x03\x04\x03\x03");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension(dummy, T, 28, "@\x01");
  event ssl_extension(dummy, T, 21, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\x88\x0a\xeb*h\xe9\xe86\x04\xc4D2\x99t\xa5'\xce\x9b+.3\xe2\xaa\x8e\xd5\xb2s\xbe", "\xbfj\xed\x7f\x07\x11\xfc&\x8ew_\x95\x99]\xa1\xd3l\xe0\x85\xacz\x15@n\xa1\x83-\xbb\x90B\xb5s", vector(4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53), vector(0));
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 0, "");
  event ssl_extension(dummy, F, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension_application_layer_protocol_negotiation(dummy, F, vector("http/1.1"));
  event ssl_extension(dummy, F, 16, "\x00\x09\x08http/1.1");
  event ssl_extension(dummy, F, 23, "");
  event ssl_extension_signature_algorithm(dummy, F, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event connection_state_remove(dummy);
}

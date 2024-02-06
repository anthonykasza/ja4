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

  event ssl_extension_server_name(dummy, T, vector("www.heise.de"));
  event ssl_extension(dummy, T, 0, "\x00\x0f\x00\x00\x0cwww.heise.de");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension(dummy, T, 10, "\x00\x0c\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("http/1.1"));
  event ssl_extension(dummy, T, 16, "\x00\x09\x08http/1.1");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension(dummy, T, 34, "\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03");
  event ssl_extension(dummy, T, 51, "\x00i\x00\x1d\x00 \x9c\xe7\xa6\x84\x90\xd2\x87\xba\x84\x831\xbe\xdb\xd6\xe1a\xa3d\xfe\xdc\xfb\x8fM\x88\xd22\xc2\xf9\x14S\x8f2\x00\x17\x00A\x04\x9f\xa1\x96h\xfd\xef\xd7\x81,\xe7\xc4\x87\x06\xe4B\x97\x1b\x0c\x00\x83j\xba\H\xf0!\xc2\x1dF}\x9b\xba6\x8aR\xcfV\xcb%\xfb\xd2_x\x09OO\xf1\x98f\xbe\xaf4S(,\xd0\xb4\x11z\xaav\x16\xa7\xb6");
  event ssl_extension_supported_versions(dummy, T, vector(772, 771));
  event ssl_extension(dummy, T, 43, "\x04\x03\x04\x03\x03");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension(dummy, T, 28, "@\x01");
  event ssl_extension(dummy, T, 21, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xcb?\x93\xd2U\xcb\xb6V%\x87\xf0\xdd\x01\x02\x12\xfd\xee\x9d#:\xffd\xe6\xed6\xcd\E", "z\x0f\x0f~I\x88\x1b\xedB\x0d\xc3\x19>\xc5\xb5\x92\x93\x95\xa7\xa4\x92/R\x8c\x8b\xef\xd5\xc2\xf8\xc5!f", vector(4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53), vector(0));
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 0, "");
  event ssl_extension_application_layer_protocol_negotiation(dummy, F, vector("http/1.1"));
  event ssl_extension(dummy, F, 16, "\x00\x09\x08http/1.1");
  event ssl_extension(dummy, F, 11, "\x01\x00");
  event ssl_extension(dummy, F, 23, "");
  event connection_state_remove(dummy);
}

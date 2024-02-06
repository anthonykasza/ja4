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

  event ssl_extension_server_name(dummy, T, vector("www.google.de"));
  event ssl_extension(dummy, T, 0, "\x00\x10\x00\x00\x0dwww.google.de");
  event ssl_extension(dummy, T, 10, "\x00\x06\x00\x1d\x00\x17\x00\x18");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("h3", "h3-29", "h3-28", "h3-27"));
  event ssl_extension(dummy, T, 16, "\x00\x15\x02h3\x05h3-29\x05h3-28\x05h3-27");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01");
  event ssl_extension(dummy, T, 51, "\x00$\x00\x1d\x00 xL\xdc\xf7\x00\xb201MiW\xf5\xdb\xd7\xc2\xc0>\x0e\xe1\x1f\xc6K@\x92\x8cA\x11\xfcM`K\x19");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension_supported_versions(dummy, T, vector(772));
  event ssl_extension(dummy, T, 43, "\x02\x03\x04");
  event ssl_extension(dummy, T, 57, "\x01\x02S\x88\x03\x04\x80\x00\xff\xf7\x04\x04\x80\x10\x00\x00\x05\x04\x80\x02\x00\x00\x06\x04\x80\x02\x00\x00\x07\x04\x80\x02\x00\x00\x08\x02@d\x09\x02@d\x0a\x01\x03\x0b\x01\x19\x0c\x00\x0f\x14\xe5\xeck&XB)\xbe\x98\xa1d4\x9a\xe9\x105\x1c@\xd1\x0b");
  event ssl_client_hello(dummy, 771, 771, network_time(), "`7\xa9\xb3\xd7\xa4T\xfe\x1aA]\xcf\xf1y\xdf\x93\.\x0f\xdd\xf5\xdf.\xf1\xc8\xdaL\xc8", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(4865, 4866, 4867), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 51, "\x00\x1d\x00 \xf4\x9b\xa4 &\x04\x01\xc3\x8b\x13\x06\xc3s\x04/\xf1\xb8\xac6\x8a\x88Az\xf6]v\xb2l\x1ay\x1fw");
  event ssl_extension_supported_versions(dummy, F, vector(772));
  event ssl_extension(dummy, F, 43, "\x03\x04");
}

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

  event ssl_extension(dummy, T, 19018, "");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension_server_name(dummy, T, vector("tls13.crypto.mozilla.org"));
  event ssl_extension(dummy, T, 0, "\x00\x1b\x00\x00\x18tls13.crypto.mozilla.org");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension(dummy, T, 18, "");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("h2", "http/1.1"));
  event ssl_extension(dummy, T, 16, "\x00\x0c\x02h2\x08http/1.1");
  event ssl_extension(dummy, T, 30032, "");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension(dummy, T, 51, "\x00)\x9a\x9a\x00\x01\x00\x00\x1d\x00 \xd9[\xee\xcc \x91\xf2\xec\x86.\xa2\xcf\xf3\xae\xf1\xec\x8ae\x87\x7f\xf5\x94\xa0@\xc9J\xc8x\xa2EW1");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension_supported_versions(dummy, T, vector(56026, 32535, 771, 770, 769));
  event ssl_extension(dummy, T, 43, "\x0a\xda\xda\x7f\x17\x03\x03\x03\x02\x03\x01");
  event ssl_extension(dummy, T, 10, "\x00\x08\x9a\x9a\x00\x1d\x00\x17\x00\x18");
  event ssl_extension(dummy, T, 24, "\x00\x10\x01\x02");
  event ssl_extension(dummy, T, 31354, "\x00");
  event ssl_extension(dummy, T, 21, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\x0a\x9c\xd2o}\x89\xb58\xc8=E\x0c`\xc19?\x14WL2i\xaf\x7fm\x10R\xbb\x8f", "\x1f\x9f#\x85\x11\xd3\xac\x9di\xed)\xb1,%\xc5n\x15\x92C\x1a\xda\xb4K9\xf8g\xef\xf6\xca\x99(n", vector(39578, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 10), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 51, "\x00\x1d\x00 \xfc\xd8\xd6\xab\x0e}~\xcae@\xf6\x09\xde/\x0f\xe8\x0e\x0eY\xfc 0\x9d\x06\x8e\xf1\x7f\xf2\xf1ei]");
  event ssl_extension_supported_versions(dummy, F, vector(32535));
  event ssl_extension(dummy, F, 43, "\x7f\x17");
}

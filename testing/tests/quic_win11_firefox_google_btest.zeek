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

  event ssl_extension_server_name(dummy, T, vector("www.google.com"));
  event ssl_extension(dummy, T, 0, "\x00\x11\x00\x00\x0ewww.google.com");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension(dummy, T, 10, "\x00\x12\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("h3"));
  event ssl_extension(dummy, T, 16, "\x00\x03\x02h3");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension(dummy, T, 34, "\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03");
  event ssl_extension(dummy, T, 51, "\x00$\x00\x1d\x00 \x95\x19>\xc2+\x81\xf0B\xb7\xd1\xcb\xd7\xea\xde\xb9\x1e6\x93\xa9/\xb1O\x1d\x9a\xc5Q40\x15J4\x06");
  event ssl_extension_supported_versions(dummy, T, vector(772));
  event ssl_extension(dummy, T, 43, "\x02\x03\x04");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x16\x04\x03\x05\x03\x06\x03\x02\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x01");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension(dummy, T, 28, "@\x01");
  event ssl_extension(dummy, T, 57, "\x0c\x00 \x01\x00\x0f\x03!3\xc4\x04\x04\x81\x80\x00\x00\x07\x04\x80\x10\x00\x00\x08\x01\x10\x09\x01\x10\x0b\x01\x14\x05\x04\x80\xc0\x00\x00\x06\x04\x80\x10\x00\x00j\xb2\x00\x01\x04\x80\x00u0\xc0\x00\x00\x00\xff\x02\xde\x1a\x02C\xe8\x0e\x01\x08");
  event ssl_extension(dummy, T, 21, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  event ssl_client_hello(dummy, 771, 771, network_time(), "\xf5\xbc\xac\xc5\x96\x0c\xc2\xea~s\xdb\xf6\xc1O\xb3\xd7,\x84\x88\x8e`\xed\xee\W?\xc2\xe6", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(4865, 4867, 4866), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 51, "\x00\x1d\x00 \xb7HT\x14yy\x02o\x11\xe4\x8a!\x05tT)\xcd\xfe7R\xb3K\x0b\x17\xcb\xb5\xbc\xb0[9)z");
  event ssl_extension_supported_versions(dummy, F, vector(772));
  event ssl_extension(dummy, F, 43, "\x03\x04");
}

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

  event ssl_extension(dummy, T, 51, "\x00$\x00\x1d\x00 \xe8jY\xf8}N&\x83\xd8\xd4\xa1S\xa3\x83\xec`\x0a`#\x94\xa2\xf2\x03M\xf4\xfe\x8e\xe1\xe0\xa3\x82y");
  event ssl_extension(dummy, T, 57, "\x80\x00GR\x04\x00\x00\x00\x01\xfe\x1e\xaf\xac\xee\x01EP\x0f<\xe0\x99\xa1\xdfT\x9f\xdeT\xa9\xe1\xbd\x1f\xd1\xe4 \x04\x80\x01\x00\x00\x01\x04\x80\x00u0\x06\x04\x80`\x00\x00\x04\x04\x80\xf0\x00\x00\x07\x04\x80`\x00\x00\x08\x02@d\x80\xffs\xdb\x0c\x00\x00\x00\x01\x9ajzJ\x00\x00\x00\x01\x09\x02@g\x05\x04\x80`\x00\x00\x0f\x00\x03\x02E\xc0q(\x04RVCM");
  event ssl_extension_server_name(dummy, T, vector("www.google.de"));
  event ssl_extension(dummy, T, 0, "\x00\x10\x00\x00\x0dwww.google.de");
  event ssl_extension(dummy, T, 17513, "\x00\x03\x02h3");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01");
  event ssl_extension_supported_versions(dummy, T, vector(772));
  event ssl_extension(dummy, T, 43, "\x02\x03\x04");
  event ssl_extension(dummy, T, 10, "\x00\x06\x00\x1d\x00\x17\x00\x18");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("h3"));
  event ssl_extension(dummy, T, 16, "\x00\x03\x02h3");
  event ssl_extension(dummy, T, 27, "\x02\x00\x02");
  event ssl_client_hello(dummy, 771, 771, network_time(), "W.{l\x0c\xf7\xf5j\xd5\x92\x0b(\xc5{\x0e\xb4g\x0fCoU\x81\xa9r\xc9\xf3'\xbb", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(4865, 4866, 4867), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 51, "\x00\x1d\x00 \xf9`\x82L\xd9\x98\xe9\xda\xcfJ\x14\xa6-\xe2\x134\xc9\x13~\xc4\x15-\x0c8\xba\xec\xaf\xf8\xf1Y\xbaD");
  event ssl_extension_supported_versions(dummy, F, vector(772));
  event ssl_extension(dummy, F, 43, "\x03\x04");
}

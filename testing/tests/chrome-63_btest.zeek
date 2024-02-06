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

  event ssl_extension(dummy, T, 43690, "");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension_server_name(dummy, T, vector("tls.ctf.network"));
  event ssl_extension(dummy, T, 0, "\x00\x12\x00\x00\x0ftls.ctf.network");
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
  event ssl_extension(dummy, T, 40, "\x00)\xca\xca\x00\x01\x00\x00\x1d\x00 \x02+\xf7\x80\xc2\x1cS\x0e:\xf8\x92q\x0c\x0b\xc1\xa5\x14\x03\xa7<\x06\xb5\xe6\x1eN\xf0\x16??\xe6\xb1S");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension_supported_versions(dummy, T, vector(31354, 32257, 771, 770, 769));
  event ssl_extension(dummy, T, 43, "\x0azz~\x01\x03\x03\x03\x02\x03\x01");
  event ssl_extension(dummy, T, 10, "\x00\x08\xca\xca\x00\x1d\x00\x17\x00\x18");
  event ssl_extension(dummy, T, 24, "\x00\x0d\x01\x02");
  event ssl_extension(dummy, T, 39578, "\x00");
  event ssl_extension(dummy, T, 21, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  event ssl_client_hello(dummy, 771, 769, network_time(), "u\xdf\x03\xfd%z\x91\xd5u\x814\xeeri\xc7i\xa7\xf7z\x1eK\x86\x14u\xf8u\xef*", "\xa7\xda\xf7\xcf\xff|#|\x0e\x99\xc6*o\xb8\xab\xf3\xc4\xad\xc0\xef)\x08\xf9\xac,\xfe\xabhV\x1f\xd9w", vector(60138, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 10), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 40, "\x00\x1d\x00 &}\xc2e\x99\x9e\xbey\xbe\x04\x00\xa0\x88\\xebr\xb25\x07\xd8\x1f\xe0\xaa\xab\xce\x90:*\xbc\xc5q\x7f");
  event ssl_extension_supported_versions(dummy, F, vector(32257));
  event ssl_extension(dummy, F, 43, "~\x01");
}

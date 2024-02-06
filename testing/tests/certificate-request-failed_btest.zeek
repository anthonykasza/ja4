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

  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x00\x14\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00(\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03\x02\x04\x02\x05\x02\x06\x02");
  event ssl_extension_supported_versions(dummy, T, vector(772, 771));
  event ssl_extension(dummy, T, 43, "\x04\x03\x04\x03\x03");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension(dummy, T, 51, "\x00$\x00\x1d\x00 \xa4,\xa5DE\xda\xb2\xf1N\xe0\x89\xb3\x12#\xbe_\x95`$\x8a;\xa8\x19\xfa\xd5\xb8\x1fDp\xac\xbeh");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xdck\"\xb8\x87\xc1\x97sG\xa8\xc1r\x874}2\xe4\x10g\"`\xd1fY?-td", "\xd2@%l\x0f\xde\x07\x81\xea\xde\xa1&\xd2\xa8\xf5[\xff\x01e\x87\x1a\xea\xea\xa9\xde\x01\xcfsr;06", vector(4866, 4867, 4865, 49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension(dummy, F, 23, "");
  event ssl_extension_signature_algorithm(dummy, F, vector([$HashAlgorithm=4, $SignatureAlgorithm=1]));
}

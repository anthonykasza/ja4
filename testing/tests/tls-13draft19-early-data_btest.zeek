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
  event ssl_extension(dummy, T, 10, "\x00\x08\x00\x1d\x00\x17\x00\x19\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00\x1e\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01\x02\x02\x04\x02\x05\x02\x06\x02");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_supported_versions(dummy, T, vector(32531, 771, 770, 769));
  event ssl_extension(dummy, T, 43, "\x08\x7f\x13\x03\x03\x03\x02\x03\x01");
  event ssl_extension(dummy, T, 45, "\x02\x01\x00");
  event ssl_extension(dummy, T, 40, "\x00$\x00\x1d\x00 \xf5\xfc\xc6\x94\xb7\xf6\xbdd\xbc\xc9\x88i\x94_\xfcg\x96\x0d\x04\xbb\x9c\x09M\xd9\xa3d\xccJ\x84=l@");
  event ssl_client_hello(dummy, 771, 769, network_time(), "y\x83\x7fU\xe4-\xa6\xd5\x1c\x87\xdc\xa3]`{\xec\x9f\x89\x07}\xba\x90\xe2s\x99\xc3\xf2\x82", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 4866, 4867, 4865, 61, 60, 53, 47, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 40, "\x00\x1d\x00 -\x84\x98/\x1f\xd0u\xf6p\xfe\x1a8\xc8\xcb\xa2m\x14Oz\xae\x9f\xa7e6*\x8cs\x17E\x09\x9au");
  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x00\x08\x00\x1d\x00\x17\x00\x19\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00\x1e\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01\x02\x02\x04\x02\x05\x02\x06\x02");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_supported_versions(dummy, T, vector(32531, 771, 770, 769));
  event ssl_extension(dummy, T, 43, "\x08\x7f\x13\x03\x03\x03\x02\x03\x01");
  event ssl_extension(dummy, T, 45, "\x02\x01\x00");
  event ssl_extension(dummy, T, 40, "\x00$\x00\x1d\x00 JC\x9f\xb83\xa0\x82]\xcd\xc7[\xc0QH\xa4\x05bU9\xe4\x98'&g\x0a- \xd5\xea\xab=%");
  event ssl_extension(dummy, T, 42, "");
  event ssl_extension(dummy, T, 41, "\x00\xb6\x00\xb0\x01\xf3\x88\x12\xae\xeb\x13\x01\xed]\xcf\x0b\x8f\xad\xf2\xc1I\x9f-\xfa\xe1\x98\x9f\xb7\x82@\x81Or\x0e\xbe\xfc\xa3\xbc\x8f\x03\x86\xf1\x8e\xae\xd7\xe5\xa2\xee\xf3\xde\xb7\xa5\xf6\\xeb\x18^ICPm!|\x09\xe0NE\xe8\x0f\xda\xf8\xf2\xa8s\x84\x17>\xe5\xd9!\x19\x09\xfe\xdb\xa87\x05\xd7\xd06JG\xeb\xad\xf9\xf8\x13?#\xdc\xe7J\xad\x14\xbfS.\x98\xd8\xd2r\x01\xef\xc5\x0c_\xdf\xc9[7\xa7l\xa7\xa0\xb5\xda\x83\x16\x10\xa1\xdb\xe2<j\xfeN=uU\xd3\xf3[\x021\xb1\xff\xcc\xbbZ\x1d\xab\x14=\xca\x80\x07!d\x06\xbe\xc6\x90\x94\x92S\xcfu\x8e\x92_/\xc9\xf0H\xf3\xd0\xfa\xeb\xb6&T_m5\x0010\xdcJ$\x00L\x12\x87\x929wEed\xbd\xf6\xcb4\x04ip5\x95\xe2X\xca[Kx}\xadHY\xae\xab\xedz\xb3\xcaK=\xa0\x09ER\x0a\x8dO\xe4");
  event ssl_client_hello(dummy, 771, 769, network_time(), ";\x03v\xb1pU\xb2Hf\x8d2\x02\xbb\xe8\xa9\xb90/\xeb\xe9?\xfe;j\xcf\xa1d8", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 4866, 4867, 4865, 61, 60, 53, 47, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 40, "\x00\x1d\x00 \xbfu\xe6\xcf\xf2\xb9\xdaA\xae;\xb3\x9c\xd2\xc7\xe2<\xc0\x81O\x0b\xd1@\xc8\xb8\x7fd\xdd-\x11\xc6n\x11");
  event ssl_extension(dummy, F, 41, "\x00\x00");
}

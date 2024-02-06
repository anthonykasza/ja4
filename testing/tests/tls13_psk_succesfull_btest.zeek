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
  event ssl_extension(dummy, T, 10, "\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=2, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00.\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x02\x03\x03\x01\x02\x01\x03\x02\x02\x02\x04\x02\x05\x02\x06\x02");
  event ssl_extension_supported_versions(dummy, T, vector(772, 771, 770, 769));
  event ssl_extension(dummy, T, 43, "\x08\x03\x04\x03\x03\x03\x02\x03\x01");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension(dummy, T, 51, "\x00$\x00\x1d\x00 \x06\x84,\x19\x1a\x9a\xd3\xc9\x00/.r\xbb\x18\xa7\x8cBQ\xa0o*l\xe0\x7ft\x0el\xc1\xb5\xed1m");
  event ssl_extension(dummy, T, 41, "\x00\x15\x00\x0fClient_identity\x00\x00\x00\x00\x00! \xdbm7\xb6\xb9\xa3\xb29C\xb5\xa3\xa4\8\x95\x94o\x8d'\xd7\x99\x91R\xea\xcb\xa82\x9cb$e\xe9");
  event ssl_client_hello(dummy, 771, 769, network_time(), "Y\xfd\x97ha\xb6\xdf\xa4I\xb3\x19r\xea\xcb\xba\x98\xbf\xe1u;\xe34\x99\x0fV\x1f!\x8b", "G\x84+\xdf.\x7fx\x99\x8cuC\xfdL\xa8V.<\xe6\xaf\x1e\x89\xa9\x87\xdcV\x9b\xa32\xab\xfd\xdb\x9f", vector(4866, 4867, 4865, 49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 173, 171, 52398, 52397, 52396, 157, 169, 52395, 172, 170, 156, 168, 61, 60, 49208, 49206, 183, 179, 149, 145, 53, 175, 141, 49207, 49205, 182, 178, 148, 144, 47, 174, 140, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension_supported_versions(dummy, F, vector(772));
  event ssl_extension(dummy, F, 43, "\x03\x04");
  event ssl_extension(dummy, F, 51, "\x00\x1d\x00 \x05\x944u\xc0\xf2\xadw\xf5\xa4\xd7\xb3I\xa7Z)\xa0'\x92~O\x7f\xde\x83#\xdb\xc56\xa1\x93\x0b\x0e");
  event ssl_extension(dummy, F, 41, "\x00\x00");
}

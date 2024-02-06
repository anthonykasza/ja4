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

  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x002\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=2], [$HashAlgorithm=2, $SignatureAlgorithm=3]));
  event ssl_extension(dummy, T, 13, "\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03");
  event ssl_extension(dummy, T, 15, "\x01");
  event ssl_client_hello(dummy, 771, 769, network_time(), ";\xa7\x98\xff\xe1\x07*\xbdP^-\x13\xd1\xec\xf3\xd1\x8ah\xcd\xba\x120\xa4\x09\xf1\x9dO\xf1", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49200, 49196, 49192, 49188, 49172, 49162, 163, 159, 107, 106, 57, 56, 136, 135, 49202, 49198, 49194, 49190, 49167, 49157, 157, 61, 53, 132, 49199, 49195, 49191, 49187, 49171, 49161, 162, 158, 103, 64, 51, 50, 154, 153, 69, 68, 49201, 49197, 49193, 49189, 49166, 49156, 156, 60, 47, 150, 65, 7, 49169, 49159, 49164, 49154, 5, 4, 49170, 49160, 22, 19, 49165, 49155, 10, 21, 18, 9, 20, 17, 8, 6, 3, 255), vector(1, 0));
  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x002\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=2], [$HashAlgorithm=2, $SignatureAlgorithm=3]));
  event ssl_extension(dummy, T, 13, "\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03");
  event ssl_extension(dummy, T, 15, "\x01");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xf4\xad\xfb\xe8\xfc\xec\xf9\xbe\x14n\xfe.\xa3\xdb\xa5\xab\xe5\x86]\xa0i\x19c\x09v\x86\xf9q", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49200, 49196, 49192, 49188, 49172, 49162, 163, 159, 107, 106, 57, 56, 136, 135, 49202, 49198, 49194, 49190, 49167, 49157, 157, 61, 53, 132, 49199, 49195, 49191, 49187, 49171, 49161, 162, 158, 103, 64, 51, 50, 154, 153, 69, 68, 49201, 49197, 49193, 49189, 49166, 49156, 156, 60, 47, 150, 65, 7, 49169, 49159, 49164, 49154, 5, 4, 49170, 49160, 22, 19, 49165, 49155, 10, 21, 18, 9, 20, 17, 8, 6, 3, 255), vector(1, 0));
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension(dummy, F, 15, "\x01");
  event connection_state_remove(dummy);
  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x002\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=2], [$HashAlgorithm=2, $SignatureAlgorithm=3]));
  event ssl_extension(dummy, T, 13, "\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03");
  event ssl_extension(dummy, T, 15, "\x01");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\x0a\x01m\xa9bE\xca#q\xe8\x01\xf8\x1eg\xca\x13o\x17>d\xd6f\xd1$L\xa7\xfd!", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49200, 49196, 49192, 49188, 49172, 49162, 163, 159, 107, 106, 57, 56, 136, 135, 49202, 49198, 49194, 49190, 49167, 49157, 157, 61, 53, 132, 49199, 49195, 49191, 49187, 49171, 49161, 162, 158, 103, 64, 51, 50, 154, 153, 69, 68, 49201, 49197, 49193, 49189, 49166, 49156, 156, 60, 47, 150, 65, 7, 49169, 49159, 49164, 49154, 5, 4, 49170, 49160, 22, 19, 49165, 49155, 10, 21, 18, 9, 20, 17, 8, 6, 3, 255), vector(1, 0));
  event connection_state_remove(dummy);
  event connection_state_remove(dummy);
}

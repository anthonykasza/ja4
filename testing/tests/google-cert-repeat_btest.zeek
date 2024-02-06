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
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00(\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03\x02\x04\x02\x05\x02\x06\x02");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xbe\x08\xbd\xfb$\xd9p\xd6\x1d\xc4\xef\x17\x81w\x09\xd9\xfcd\x1e}-\xbe\xf0Y\xac\x9c\x15\x1c", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 23, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x01\x00");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00(\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03\x02\x04\x02\x05\x02\x06\x02");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\x01\xc4\xc2W\x0f\xd5\xa1\xa1/h\xe9\xb9\xb8z2\xb6j\xf4\x921\xfb\xc8\x0dV\xab\xbc\x89\xb3", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 23, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x01\x00");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00(\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03\x02\x04\x02\x05\x02\x06\x02");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xe7a\x8f\x06\\xb9\xab\x8c\xd4\x0b\xfe\x07\x19vD-<1\xee\x89\xceg\x9fQ\xb9\x18g\xcf", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 23, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x01\x00");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00(\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03\x02\x04\x02\x05\x02\x06\x02");
  event ssl_client_hello(dummy, 771, 769, network_time(), "BC\xaeP#\xc0c\x94\xb8\xb6\xb6\x02*\"X\xe9\x82\xd2\x1c;\xd0\x0c\x85\xb9\xb8\x01\x83-", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 23, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x01\x00");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension_server_name(dummy, T, vector("www.google.com"));
  event ssl_extension(dummy, T, 0, "\x00\x11\x00\x00\x0ewww.google.com");
  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00(\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03\x02\x04\x02\x05\x02\x06\x02");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xdd\xcb<+.Q\xb6F8\xee\x12\xe9\xbb\xbf\xa9m\xc2\x0e\x0c\x17\x04l;\x9a\xbbKd1", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 23, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x01\x00");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension_server_name(dummy, T, vector("www.google.com"));
  event ssl_extension(dummy, T, 0, "\x00\x11\x00\x00\x0ewww.google.com");
  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00(\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03\x02\x04\x02\x05\x02\x06\x02");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xe0\xc0\xde\xb7?\xda\xdb#\x13\xaba4\x93]\xaf\x8e\xce\x82\xc1\x99Q\x06\xf8\xca\x94\x8dD~", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 23, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x01\x00");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension_server_name(dummy, T, vector("www.google.com"));
  event ssl_extension(dummy, T, 0, "\x00\x11\x00\x00\x0ewww.google.com");
  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00(\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03\x02\x04\x02\x05\x02\x06\x02");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\x98\x19@\xacPZ\x93\xcaQ\x81\xceM\xad\xb8\x9f\xc0r\xa8\x08U\x0a\x92\x01\xf0x\xce&^", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 23, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x01\x00");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension_server_name(dummy, T, vector("www.google.com"));
  event ssl_extension(dummy, T, 0, "\x00\x11\x00\x00\x0ewww.google.com");
  event ssl_extension(dummy, T, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, T, 10, "\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 22, "");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=7], [$HashAlgorithm=8, $SignatureAlgorithm=8], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=3], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=2], [$HashAlgorithm=4, $SignatureAlgorithm=2], [$HashAlgorithm=5, $SignatureAlgorithm=2], [$HashAlgorithm=6, $SignatureAlgorithm=2]));
  event ssl_extension(dummy, T, 13, "\x00(\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03\x02\x04\x02\x05\x02\x06\x02");
  event ssl_client_hello(dummy, 771, 769, network_time(), "!-\x19\x1a~]h\x8a+-\xc0\xee\x01\xa1.\x98-\xbf\x0f\xa5\x1b\xf1\x84\xff\xb39z\x0b", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 23, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x01\x00");
  event ssl_extension(dummy, F, 35, "");
}

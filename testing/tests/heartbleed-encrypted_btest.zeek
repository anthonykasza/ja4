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

  event ssl_extension_server_name(dummy, T, vector("www.lilawelt.net"));
  event ssl_extension(dummy, T, 0, "\x00\x13\x00\x00\x10www.lilawelt.net");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension(dummy, T, 10, "\x00\x06\x00\x17\x00\x18\x00\x19");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=3]));
  event ssl_extension(dummy, T, 13, "\x00\x08\x04\x01\x04\x03\x02\x01\x02\x03");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xc8M\x90\x15~\xc3\xb0i\x83Ke\xfa\x96\x84\xb9\xa6\xf3z\xe5Q\"\xd6:\xe7\x10\xe8\xf0\x0f", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49199, 49195, 49169, 49159, 49171, 49161, 49172, 49162, 5, 47, 53, 49170, 10), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 0, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x03\x00\x01\x02");
}

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

  event ssl_extension_server_name(dummy, T, vector("ssl.gstatic.com"));
  event ssl_extension(dummy, T, 0, "\x00\x12\x00\x00\x0fssl.gstatic.com");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension(dummy, T, 10, "\x00\x06\x00\x17\x00\x18\x00\x19");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 13172, "");
  event ssl_client_hello(dummy, 769, 769, network_time(), "\xc97\x10\xcfx\x9e\xf7\xaa\x0e\xd1\xdd\x9b\x8c\xd5\xcb\xc5T\xa9\xda\xfe\xc9\x931\x99\xd5BO\xd7", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49162, 49172, 136, 135, 57, 56, 49167, 49157, 132, 53, 49159, 49161, 49169, 49171, 69, 68, 102, 51, 50, 49164, 49166, 49154, 49156, 150, 65, 4, 5, 47, 49160, 49170, 22, 19, 49165, 49155, 65279, 10), vector(1, 0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 0, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension(dummy, F, 13172, "\x06spdy/2\x08http/1.1");
}

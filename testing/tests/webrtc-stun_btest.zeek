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
  event ssl_extension(dummy, T, 10, "\x008\x00\x0e\x00\x0d\x00\x19\x00\x1c\x00\x0b\x00\x0c\x00\x1b\x00\x18\x00\x09\x00\x0a\x00\x1a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11");
  event ssl_extension(dummy, T, 15, "\x01");
  event ssl_extension(dummy, T, 14, "\x00\x02\x00\x01\x00");
  event ssl_client_hello(dummy, 65279, 65279, network_time(), "\x8ev\xfa \xbf\x84\xd0[\xddQ\xe8\xce\xdb!\xdf\x8f\xa6kW\xc3zC\xb4\xa0z\x09o~", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49172, 49162, 57, 56, 55, 54, 136, 135, 134, 133, 49177, 58, 137, 49167, 49157, 53, 132, 49171, 49161, 51, 50, 49, 48, 154, 153, 152, 151, 69, 68, 67, 66, 49176, 52, 155, 70, 49166, 49156, 47, 150, 65, 7, 49170, 49160, 22, 19, 16, 13, 49175, 27, 49165, 49155, 10, 21, 18, 15, 12, 26, 9, 20, 17, 14, 11, 25, 8, 6, 49168, 49158, 49173, 49163, 49153, 2, 1, 255), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 11, "\x01\x00");
  event ssl_extension(dummy, F, 14, "\x00\x02\x00\x01\x00");
  event ssl_extension(dummy, F, 65281, "\x00");
}

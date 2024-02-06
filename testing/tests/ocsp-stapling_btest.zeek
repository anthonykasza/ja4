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
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension(dummy, T, 15, "\x01");
  event ssl_client_hello(dummy, 769, 769, network_time(), "\x8d\xc2\xb0P\xae\x8fSX\x87\xec\x8a\x03\xdbD\x0b\x1f\xaa\xa3\x88\x1b\xf3\x82\xc8\x16^\x81k\xd2", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49172, 49162, 49186, 49185, 57, 56, 136, 135, 49167, 49157, 53, 132, 49170, 49160, 49180, 49179, 22, 19, 49165, 49155, 10, 49171, 49161, 49183, 49182, 51, 50, 154, 153, 69, 68, 49166, 49156, 47, 150, 65, 7, 49169, 49159, 49164, 49154, 5, 4, 21, 18, 9, 20, 17, 8, 6, 3, 255), vector(1, 0));
  event ssl_extension(dummy, F, 5, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event connection_state_remove(dummy);
}

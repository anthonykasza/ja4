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

  event ssl_client_hello(dummy, 2, 0, network_time(), "\xe6\xb8\xef\xdf\x91\xcfD\xf7\xea\xe4<\x839\x8f\xdc\xb2", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(57, 56, 53, 51, 50, 4, 5, 47, 22, 19, 65279, 10, 21, 18, 65278, 9, 100, 98, 3, 6), vector());
  event ssl_client_hello(dummy, 769, 769, network_time(), "\xa8\xa2\xabs\x9ad\xab\xb4\xe6\x8c\xfc\xfc4p\xffbi\xb1\xa8hXP\x1f\xbb\xd12~\xd8", "\xa8\xc1\xc5h\x19$\xe8\x0a2\xa1]^\x7f \xbc^?Q>V\xb2\x15\x03\x9d\x0dU\xde\xfd\xa5\xa3 \xc0", vector(57, 56, 53, 51, 50, 4, 5, 47, 22, 19, 65279, 10, 21, 18, 65278, 9, 100, 98, 3, 6), vector(0));
  event ssl_client_hello(dummy, 769, 769, network_time(), "$\x06\x04\xbe/VD\xc8\xdf\xd2\xe5\x1c\xc2\xb3\xa3\x01q\xbdX\x85>\xd7\xc6\xe3\xfc\xd1\x88F", "\x9eQ\xca\xef@\xad\x85\xf9\xf0=\xbb\x8c\x1f\xdc\x866!\x80\x8c1\x12r\xe1\x02B\xcb@k\xf9\x17\xbc\xd9", vector(57, 56, 53, 51, 50, 4, 5, 47, 22, 19, 65279, 10, 21, 18, 65278, 9, 100, 98, 3, 6), vector(0));
  event connection_state_remove(dummy);
  event connection_state_remove(dummy);
  event connection_state_remove(dummy);
}

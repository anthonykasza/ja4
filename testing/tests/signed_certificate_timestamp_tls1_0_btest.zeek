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
  event ssl_extension(dummy, T, 10, "\x00\x1a\x00\x17\x00\x19\x00\x1c\x00\x1b\x00\x18\x00\x1a\x00\x16\x00\x0e\x00\x0d\x00\x0b\x00\x0c\x00\x09\x00\x0a");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 15, "\x01");
  event ssl_extension(dummy, T, 18, "");
  event ssl_client_hello(dummy, 769, 769, network_time(), "\xa6\x93X\x19\xe1\x17\x9d\x87R\x90\x8b\xa3x\xee\xc8\x14\xc5\xce\x1f\xc3\xd3\xcb\xa8\xfa\xbfI\xa5'", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(49172, 49162, 57, 56, 55, 54, 136, 135, 134, 133, 49167, 49157, 53, 132, 49171, 49161, 51, 50, 49, 48, 154, 153, 152, 151, 69, 68, 67, 66, 49166, 49156, 47, 150, 65, 7, 49169, 49159, 49164, 49154, 5, 4, 49170, 49160, 22, 19, 16, 13, 49165, 49155, 10, 255), vector(1, 0));
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension(dummy, F, 18, "\x00\xf2\x00w\x00\xeeK\xbd\xb7u\xce`\xba\xe1Bi\x1f\xab\xe1\x9ef\xa3\x0f~_\xb0r\xd8\x83\x00\xc4{\x89z\xa8\xfd\xcb\x00\x00\x01_x\x16\xda\x0c\x00\x00\x04\x03\x00H0F\x02!\x00\xdf\xb5E\x08<Bh\x804\x95\xf3\x82u&gI\xe0^\xca<\x8b\xf2Tw\x81#\xccV\xf7\x9d\xe9O\x02!\x00\xa4\"\x08\x91\x8c\xfbO\xcd]\xb7\xc0\xae\xca\xbf\x9e~\x99y\xa5\xdc\x0b19\xec:&#|\x14\xd9\\xe3\x00w\x00\xdd\xeb\x1d+z\x0dO\xa6 \x8b\x81\xad\x81hp~.\x8e\x9d\x01\xd5\\x88\x8d=\x11\xc4\xcd\xb6\xec\xbe\xcc\x00\x00\x01_x\x16\xdb)\x00\x00\x04\x03\x00H0F\x02!\x00\xd8\xb5)\x1e\xc3\xa2\xcb\x025\x14\xadt^*`\x9cC\x94 \xdba\xc1\xa4\x93G\x89]\xded\x1bo\x11\x02!\x00\xb6\xe3?\xe8u\xd7\xfc\x84\xd6\xf6\x9e\x98\xd2\x8fm\xcd\xad\xb1\x04\x9fAt\xcd\xe6\xbe\x95\xe2G\xef\xc5\x7fU");
  event ssl_extension(dummy, F, 11, "\x01\x00");
  event connection_state_remove(dummy);
}
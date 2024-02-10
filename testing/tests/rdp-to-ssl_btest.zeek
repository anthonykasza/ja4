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

  event ssl_extension_server_name(dummy, T, vector("192.168.1.150"));
  event ssl_extension(dummy, T, 0, "\x00\x10\x00\x00\x0d192.168.1.150");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension(dummy, T, 10, "\x00\x04\x00\x17\x00\x18");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_client_hello(dummy, 769, 769, network_time(), "\x8a\x9b}2^\xd9\x08\xde\x8c\xb2\xb4\xdeP\xec\x88\x18J\x1fn\xc7#\xc1\xd5\xa3D\xa6\xcc4", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(47, 53, 5, 10, 49171, 49172, 49161, 49162, 50, 56, 19, 4), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension_server_name(dummy, T, vector("192.168.1.150"));
  event ssl_extension(dummy, T, 0, "\x00\x10\x00\x00\x0d192.168.1.150");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension(dummy, T, 10, "\x00\x04\x00\x17\x00\x18");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_client_hello(dummy, 769, 769, network_time(), "\xcd+\xe6\xed\xe8]\xef\x1e?\xcd\x80\xdd\xfc\x00\x9a\xbb\x89\xf5\xb9\x1f\xb9\xc99q\xb3m\x99\x09", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(47, 53, 5, 10, 49171, 49172, 49161, 49162, 50, 56, 19, 4), vector(0));
  event my_finalize_ssl(dummy);
}

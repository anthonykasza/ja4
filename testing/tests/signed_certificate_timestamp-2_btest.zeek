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

  event ssl_extension(dummy, T, 43690, "");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension_server_name(dummy, T, vector("ritter.vg"));
  event ssl_extension(dummy, T, 0, "\x00\x0c\x00\x00\x09ritter.vg");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension(dummy, T, 18, "");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("h2", "http/1.1"));
  event ssl_extension(dummy, T, 16, "\x00\x0c\x02h2\x08http/1.1");
  event ssl_extension(dummy, T, 30032, "");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension(dummy, T, 40, "\x00)\xca\xca\x00\x01\x00\x00\x1d\x00 7\x18\xc9\x1cu\xc7\xb1\xa2\xa1?\x87\xaa\xf5\x08\x17-\xdetr\x1b8\x12\x0dc\xcb\xedlT\xec4z?");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension_supported_versions(dummy, T, vector(6682, 32530, 771, 770, 769));
  event ssl_extension(dummy, T, 43, "\x0a\x1a\x1a\x7f\x12\x03\x03\x03\x02\x03\x01");
  event ssl_extension(dummy, T, 10, "\x00\x08\xca\xca\x00\x1d\x00\x17\x00\x18");
  event ssl_extension(dummy, T, 24, "\x00\x0d\x01\x02");
  event ssl_extension(dummy, T, 35466, "\x00");
  event ssl_extension(dummy, T, 21, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\x1bb\xee:\xa2\x8c\xe7\xd9n\x020\x94\x9e\xd0\xa3(}R[1\\x13\xf3X[\xee\x8d\xe7", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(56026, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 10), vector(0));
  event ssl_extension(dummy, F, 0, "");
  event ssl_extension(dummy, F, 65281, "\x00");
  event ssl_extension(dummy, F, 11, "\x03\x00\x01\x02");
  event ssl_extension(dummy, F, 35, "");
  event ssl_extension(dummy, F, 5, "");
  event ssl_extension(dummy, F, 18, "\x03\x8a\x00w\x00\xa4\xb9\x09\x90\xb4\x18X\x14\x87\xbb\x13\xa2\xccgp\x0a<5\x98\x04\xf9\x1b\xdf\xb8\xe3w\xcd\x0e\xc8\x0d\xdc\x10\x00\x00\x01Zca@ \x00\x00\x04\x03\x00H0F\x02!\x00\x89\x82s\x17\xd9\xcbo\xcf\xc3\xba\x91{\xeb\xe8\xf1\xbe\xc8)\x97\x1e\xe8A\x99P\x00\xaa\xb4\x15\xd97\x93\xca\x02!\x00\xca\xcd\xec\x9e\x12\xeed/v\xf5\xc32\xba\x92S\xe0 }\x85k\xe7\xd4TRp\xe8\x8d~\xba\x9d\x12\x16\x01/\x00\xac;\x9a\xed\x7f\xa9gGW\x15\x9em}WVr\xf9\xd9\x81\x00\x94\x1e\x9b\xde\xff\xec\xa11;ux-\x00\x00\x01ZcaC\xf4\x00\x00\x04\x01\x01\x00\x04\xed\x08\xca\x8e\x1b\x8ba$\xe5\xe8{Y\x96'+\x06\x86\x87o\x1a=i5\x91\xc3\xfd\xf6\xbe\xeao;\xc8\x1c\x01j\xc0\x14\xea\x06\xd3\xe3#w,\x07\x06\xc3\xd0\xdc\xf2L:\xb0{\xfd.\x00\xdf\xc2\xb8w(\xaak\xfe^\xa0\x05\xe1\x84\xad\x1a!\xf2@/J\xcc\xcb8\xbb\xfa`;CF\<e\x17\xdafE/zX\xeb\xd0y\x15[\xd5\xe2\xee\xaf\xf8k\xeeX\x92\xa48\x0c\xab\x15v\xa6\xa4\x00\xc5Sjo\xe9\xbcL\xde\x11\x1d\x93\x7f\x9b\xbe\xb1\x13\xfb\xf1\xcb\xfb4\x85\xf2j\xc1t\xb0\x82g;*\x05i\x99*h\xe1\xcc\x07\xd2u\xc8L\xd3\x97\xb9\x81[-\xd1\xff\x1e\xc0\xa4\x80^vv\xb8+\xc5q\xec\xc0\xe7\x90\x00\x11{\xfdY\xb4fk'{\xa4T\xf4HO\xfd\x1d\xf6\xce\xbe=\x08G\x91\xd54\x0a\x90\xe7\xd5\xeda\x8c\xeb|\"\xc1r!\xd9\xfb\xbd~\xf8\xc1\x01\xb5@9|\x9e\x0ej\xd1S\x97\xa3\x0a\xf9h\x15\xd7}\x05\x8a\x1b+j\x13\xf5\x00w\x00\x03\x01\x9d\xf3\xfd\x85\xa6\x9a\x8e\xbd\x1f\xac\xc6\xda\x9b\xa7>F\x97t\xfew\xf5y\xfcZ\x08\xb82\x8c\x1dk\x00\x00\x01Zca\x96=\x00\x00\x04\x03\x00H0F\x02!\x00\x99\x8c\xa5+u\xe1t\x08\x0a\xa9!\xed)\x9b\xb6\xccx\x8d0VN,RZ2\xd93\xdc\xa7 \xa5\xd3\x02!\x00\xc8\xde\x96\x8d\x02\xd6\xfcx\xdbM \x06\x1cq\xe5\x10\xe3 \x18B\\x1d1\x88\xb0\xeb\xf3\xf2\x9b\x99X\xb4\x00v\x00V\x14\x06\x9a/\xd7\xc2\xec\xd3\xf5\xe1\xbdD\xb2>\xc7Fv\xb9\xbc\x99\x11\\xc0\xef\x94\x98U\xd6\x89\xd0\xdd\x00\x00\x01Zca<-\x00\x00\x04\x03\x00G0E\x02 F\xc2\xfb\x02\xfd\xa3RNy_\x16^\xb54-S\x90\xdbK\x97\x87\x00\x93\xa1\x0d'\xc0<\xbeu\xc4\xab\x02!\x00\xb4\x93\xbb\xe2\xee\x14X\xd4\xcf\xa4\xc1\xd8\xcf\xdaAoaD\xf0\xbbM7\xdb\xb0\xec\xca\x0f\x18\xcbe\x8d\xe9\x00u\x00\xeeK\xbd\xb7u\xce`\xba\xe1Bi\x1f\xab\xe1\x9ef\xa3\x0f~_\xb0r\xd8\x83\x00\xc4{\x89z\xa8\xfd\xcb\x00\x00\x01ZcaB\xa7\x00\x00\x04\x03\x00F0D\x02 I\x06\xb4\x84Zo\xf49\x85\xd2\xbb\xc8\x8bb\x9b\xac\xbd\x84\x00\xf2f\xd0\x14\x0cV\x15_\xc7\x09&\xc1\x9f\x02 M\x0c\x05\x01ab\xe5\x97\xf9\xf8'\x02\xf4\x198\x97\xd2>xa\xc2\xda\xc1saw\xd8]\xc8\x97\xd6]\x00v\x00\xbb\xd9\xdf\xbc\x1f\x8aq\xb5\x93\x94#\x97\xaa\x92{G8W\x95\x0a\xabR\xe8\x1a\x90\x96d6\x8e\x1e\xd1\x85\x00\x00\x01Zca:\x86\x00\x00\x04\x03\x00G0E\x02!\x00\xb1\x1atJ4\x80\xbd\xc5\x97\x7f(\xae^N\xe3WE-AO\x14X\x0aB\x1e\xc4\xb36\x00TVg\x02 o1hk\xec\x9fFG\xa4\xd2&\x97>E\x87\x7f\xcf\x1c\xc8\xdb>j\xc9\xde\xf5\x1e\x97\xf8\xc3e\xcc\x11");
  event ssl_extension_application_layer_protocol_negotiation(dummy, F, vector("h2"));
  event ssl_extension(dummy, F, 16, "\x00\x03\x02h2");
  event connection_state_remove(dummy);
}

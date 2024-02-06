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

  event ssl_extension(dummy, T, 56026, "");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("h2", "http/1.1"));
  event ssl_extension(dummy, T, 16, "\x00\x0c\x02h2\x08http/1.1");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=6, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01");
  event ssl_extension(dummy, T, 51, "\x00)\x1a\x1a\x00\x01\x00\x00\x1d\x00 #\x1c\xb3\xa7\xbd\xe0\xd1]\x97\xdf\xdf\xc4\xd3\x15\xb1\x12\x89\x9e\x94\x80\xd1\xdcz\x0es\x9c@X\xbb\xe7'm");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension(dummy, T, 17513, "\x00\x03\x02h2");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension_supported_versions(dummy, T, vector(35466, 772, 771));
  event ssl_extension(dummy, T, 43, "\x06\x8a\x8a\x03\x04\x03\x03");
  event ssl_extension(dummy, T, 10, "\x00\x08\x1a\x1a\x00\x1d\x00\x17\x00\x18");
  event ssl_extension(dummy, T, 65037, "\x00\x00\x01\x00\x01\xd1\x00 \xcc\xe5\xc82\x99\xbb\x8d\xff\xdbt\xba\xfd\x0a\x1dRK\x82\x97>\"L\x12\x99\x9b\xee\xd1i\xeez\x9a\xd6}\x00\x90\x0b{-\xc3\xb1z\xdb.\xab\xc1\xf7\xfa\xbba\xbd\xd5\xdbws6\xa9\xda6y\xc57?\xf6\x9f\x00\x87\xb9E;\xd3\xecB\xb6\xd1{\x1b}\x02L\xd7\xc4\xb6'\xd1\xb0\xcd:\xe9\xfb\xe5B/\x13!\x87x\x9dl\x7f\x89\xf2\x92\x01\xff\x0ed\x85=9\x88\xad\xb7#\xff\xf5RD~\xbd\x08zUB*\xbeV\x8a\x8d\xfeE\x96\xa5\x82\x0f\x13N\xc9\xf1\x92b\x0eK6wd1\xe1N5\xa6\xc9\xdd\xbe\x91#Y\xb1\xbd\xe0\xd7J\x06.cN\xb5\xce\xd3\x06;\xed\x83\xf0\xb5b\xf2bx\x03");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension(dummy, T, 18, "");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension_server_name(dummy, T, vector("cloudflare-ech.com"));
  event ssl_extension(dummy, T, 0, "\x00\x15\x00\x00\x12cloudflare-ech.com");
  event ssl_extension(dummy, T, 27, "\x02\x00\x02");
  event ssl_extension(dummy, T, 39578, "\x00");
  event ssl_extension(dummy, T, 21, "\x00\x00\x00\x00\x00\x00\x00");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\x1f\xb4\xdc:p\xfa\xc9\x1f\x13Y\xff^2\x0cj^\x079z\xb3o\x8cQ;\xe4X_]", "|w\xf9h\xec\xbe\xda\x04\x05\x98\xf4z\xf5&_\xb5\xf0\xf5\xef2y\xf0\x8bC\xd0<1\xa5|\xe0\xc60", vector(10794, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53), vector(0));
  event ssl_extension_supported_versions(dummy, F, vector(772));
  event ssl_extension(dummy, F, 43, "\x03\x04");
  event ssl_extension(dummy, F, 51, "\x00\x1d\x00 \x0f\xf6\xe1E-2fj\x006\xd0\x07\x1d\xbf\xce\xad\xdcd\x8e-Z\xa6\xfd\x1cS\x0c?\x15\xf8#'\x1f");
  event ssl_extension(dummy, T, 47802, "");
  event ssl_extension(dummy, T, 10, "\x00\x08\xda\xda\x00\x1d\x00\x17\x00\x18");
  event ssl_extension(dummy, T, 35, "");
  event ssl_extension(dummy, T, 17513, "\x00\x03\x02h2");
  event ssl_extension(dummy, T, 11, "\x01\x00");
  event ssl_extension(dummy, T, 65037, "\x00\x00\x01\x00\x01\xd1\x00 U9\x8d\xbe\x11\x13x\xd8\x85\xe0\xa5h\xf0\x01?\x16\xcb\xca{\x99\xfe\xc6{\x02\xdfZ\xd2~\xb3}\xb1K\x00\x90\xef\xf7\x10\x08\xe1S~\xa8\xe6\x11\xdb\xe31vO\x995`\xb2\xba7\x0f\x9f\x86\xabT(\xb2]\xd2\xe1\xb9d\x90\"\xa6\x01\xa5\xc6\xce\xc5z\xc0\xd8)Q\x84\xcdc\xe0R\xba\xfc\x16\xfe\xe0\xdf\xe5\x19A\x7f\Z$\xc8\x93\xc4\x00\xf3<\x8a\xee\xe2\x85x'\xcc\x9eZ\x16\x96pw\x04wx\xdba\x81\xfc\xad\xc2g[z\x81\xf448}`\xf1\xd5\xf29g\x8b\xfe\xe8\xd3\x1c\xfbs\x96U\xf8\xa5\xe2\xb9\x99\x9ff2\x89o~\x81\x0by\xad\xd0\xdcE\xda,\x89\xcc\xc2\x14\x1c\xe4\x12\x90\x1b");
  event ssl_extension(dummy, T, 65281, "\x00");
  event ssl_extension(dummy, T, 18, "");
  event ssl_extension(dummy, T, 5, "\x01\x00\x00\x00\x00");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=6, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01");
  event ssl_extension(dummy, T, 27, "\x02\x00\x02");
  event ssl_extension(dummy, T, 45, "\x01\x01");
  event ssl_extension(dummy, T, 23, "");
  event ssl_extension_server_name(dummy, T, vector("cloudflare-ech.com"));
  event ssl_extension(dummy, T, 0, "\x00\x15\x00\x00\x12cloudflare-ech.com");
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("h2", "http/1.1"));
  event ssl_extension(dummy, T, 16, "\x00\x0c\x02h2\x08http/1.1");
  event ssl_extension_supported_versions(dummy, T, vector(14906, 772, 771));
  event ssl_extension(dummy, T, 43, "\x06::\x03\x04\x03\x03");
  event ssl_extension(dummy, T, 51, "\x00)\xda\xda\x00\x01\x00\x00\x1d\x00 J\xe0\x9d#\x82\x00\xbc\xee\x17\xa3.\\xa0\x14\x83\"n\xaf4k\xf3\x16\x006V\xe2~\x9b\xd6W\xf8!");
  event ssl_extension(dummy, T, 64250, "\x00");
  event ssl_extension(dummy, T, 21, "\x00\x00\x00\x00\x00\x00\x00");
  event ssl_client_hello(dummy, 771, 769, network_time(), "\xbd\xdcC[\x81&\xc5\xe3w\x09|\xf2\x8a\xf4\xe4\x13\xa6\xbep\xd3\x90\xe4\x9a3\xf0\x8e\xd8\x98", "\xbc\x8fJ\xacJ\xcd\xa8\x1dkz\x96{E\xa6\x0c7\x92\xfeJ3\xa1K\xa7\xde\x9d\x0b\xcc\xb6GYq\x94", vector(27242, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53), vector(0));
  event ssl_extension_supported_versions(dummy, F, vector(772));
  event ssl_extension(dummy, F, 43, "\x03\x04");
  event ssl_extension(dummy, F, 51, "\x00\x1d\x00 \x8e\xcc\x94\xecZ\x96\xc2\xe9q\xf1(\x93\xdd\xd4\xda\xa3+\xe8\x10\xa6\xb7\xc9\x06q\"y\x8a\xcd\x0e\x96\x07-");
  event connection_state_remove(dummy);
  event connection_state_remove(dummy);
  event connection_state_remove(dummy);
}

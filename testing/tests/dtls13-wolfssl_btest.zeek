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

  event ssl_extension(dummy, T, 51, "\x00E\x00\x17\x00A\x04\xed\xd89Z\x8f\x8d%p{K\xa4>J\x9a?\xae\xe4\xffBH\x96vg\xfbBW\xc4\x07\xc9MP\xca?o\x93\xc0\x1d\x954\x89b\x0c\xe3\x12!\xc5?o\x0f\x13\xd3\x1a\xa5A\x818\xd2\xa0Z\x00\xa9\xb6\xaf?");
  event ssl_extension_supported_versions(dummy, T, vector(65276));
  event ssl_extension(dummy, T, 43, "\x02\xfe\xfc");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x1e\x06\x03\x05\x03\x04\x03\x02\x03\x08\x06\x08\x0b\x08\x05\x08\x0a\x08\x04\x08\x09\x06\x01\x05\x01\x04\x01\x03\x01\x02\x01");
  event ssl_extension(dummy, T, 10, "\x00\x0a\x00\x19\x00\x18\x00\x17\x00\x15\x01\x00");
  event ssl_extension(dummy, T, 22, "");
  event ssl_client_hello(dummy, 65277, 65277, network_time(), "\x94\xfb6e\x8f \x88\xe6)\xd2\x92:\xd45\x88$\x16>0\xb8q_R\xb5`\xe6a\xd1", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(4865, 4866, 4867, 49196, 49195, 49200, 49199, 159, 158, 52393, 52392, 52394, 49191, 49187, 49192, 49188, 49162, 49161, 49172, 49171, 107, 103, 57, 51, 52244, 52243, 52245), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension_supported_versions(dummy, F, vector(65276));
  event ssl_extension(dummy, F, 43, "\xfe\xfc");
  event ssl_extension(dummy, F, 44, "\x00C h\x1e\x0d\xd7vlV?M\x9b\xf4G\xd4*\xaf\xf9\x02\x16\x7fJ\xb5)\x13r\xea\xcc,\x1c,i}3\x13\x01\xbc\x80\xbe\xf9\xeb\xf4w`\x99\xaa>\x8f@\x1f\x0fU\xb7_\x01=\xe8P\xac\x9c>\x0dK\xa4R\xee`\x95");
  event ssl_extension_supported_versions(dummy, T, vector(65276));
  event ssl_extension(dummy, T, 43, "\x02\xfe\xfc");
  event ssl_extension(dummy, T, 44, "\x00C h\x1e\x0d\xd7vlV?M\x9b\xf4G\xd4*\xaf\xf9\x02\x16\x7fJ\xb5)\x13r\xea\xcc,\x1c,i}3\x13\x01\xbc\x80\xbe\xf9\xeb\xf4w`\x99\xaa>\x8f@\x1f\x0fU\xb7_\x01=\xe8P\xac\x9c>\x0dK\xa4R\xee`\x95");
  event ssl_extension(dummy, T, 51, "\x00E\x00\x17\x00A\x04\xed\xd89Z\x8f\x8d%p{K\xa4>J\x9a?\xae\xe4\xffBH\x96vg\xfbBW\xc4\x07\xc9MP\xca?o\x93\xc0\x1d\x954\x89b\x0c\xe3\x12!\xc5?o\x0f\x13\xd3\x1a\xa5A\x818\xd2\xa0Z\x00\xa9\xb6\xaf?");
  event ssl_extension_signature_algorithm(dummy, T, vector([$HashAlgorithm=6, $SignatureAlgorithm=3], [$HashAlgorithm=5, $SignatureAlgorithm=3], [$HashAlgorithm=4, $SignatureAlgorithm=3], [$HashAlgorithm=2, $SignatureAlgorithm=3], [$HashAlgorithm=8, $SignatureAlgorithm=6], [$HashAlgorithm=8, $SignatureAlgorithm=11], [$HashAlgorithm=8, $SignatureAlgorithm=5], [$HashAlgorithm=8, $SignatureAlgorithm=10], [$HashAlgorithm=8, $SignatureAlgorithm=4], [$HashAlgorithm=8, $SignatureAlgorithm=9], [$HashAlgorithm=6, $SignatureAlgorithm=1], [$HashAlgorithm=5, $SignatureAlgorithm=1], [$HashAlgorithm=4, $SignatureAlgorithm=1], [$HashAlgorithm=3, $SignatureAlgorithm=1], [$HashAlgorithm=2, $SignatureAlgorithm=1]));
  event ssl_extension(dummy, T, 13, "\x00\x1e\x06\x03\x05\x03\x04\x03\x02\x03\x08\x06\x08\x0b\x08\x05\x08\x0a\x08\x04\x08\x09\x06\x01\x05\x01\x04\x01\x03\x01\x02\x01");
  event ssl_extension(dummy, T, 10, "\x00\x0a\x00\x19\x00\x18\x00\x17\x00\x15\x01\x00");
  event ssl_extension(dummy, T, 22, "");
  event ssl_client_hello(dummy, 65277, 65277, network_time(), "\x94\xfb6e\x8f \x88\xe6)\xd2\x92:\xd45\x88$\x16>0\xb8q_R\xb5`\xe6a\xd1", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", vector(4865, 4866, 4867, 49196, 49195, 49200, 49199, 159, 158, 52393, 52392, 52394, 49191, 49187, 49192, 49188, 49162, 49161, 49172, 49171, 107, 103, 57, 51, 52244, 52243, 52245), vector(0));
  event my_finalize_ssl(dummy);
  event ssl_extension(dummy, F, 51, "\x00\x17\x00A\x04H\xd5\x89\x12o]\x0b\xeaJ\x14\x079uN\x89\x15\xba\x11\x87\xc1[\x87\xed\xe6)\x90;\x81jn,\xd7>~\xf8\xbe\xd7\x09p\xda\xf3\x8f\xf8]\xe4g\x85PySa\x81\xe1\x94\x91V/\xa8Y.8\xc9\x13e");
  event ssl_extension_supported_versions(dummy, F, vector(65276));
  event ssl_extension(dummy, F, 43, "\xfe\xfc");
}

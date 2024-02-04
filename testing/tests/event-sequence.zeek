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

  event ssl_extension_server_name(dummy, T, vector("AK"));
  event ssl_extension(dummy, T, 0xaaaa, "GREASE");
  event ssl_extension(dummy, T, SSL::SSL_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, ""); 
  event ssl_extension_application_layer_protocol_negotiation(dummy, T, vector("XX", "YY"));
  event ssl_extension(dummy, T, SSL::SSL_EXTENSION_SIGNATURE_ALGORITHMS, "");
  event ssl_extension_signature_algorithm(dummy, T,
    vector(
      [$HashAlgorithm=0x01, $SignatureAlgorithm=0x02],
      [$HashAlgorithm=0xfe, $SignatureAlgorithm=0xff]
    )
  );
  event ssl_extension(dummy, T, 0xaaaa, "GREASE");
  event ssl_extension(dummy, T, 0xaaaa, "GREASE");
  event ssl_extension(dummy, T, SSL::SSL_EXTENSION_SUPPORTED_VERSIONS, "");
  event ssl_extension_supported_versions(dummy, T, vector(0xabcd, 0x0));
  event ssl_client_hello(
    dummy, 0xabcd, 0xabce, double_to_time(0.0), "client_rand",
    "session_id", vector(0x2222, 0x2223, 0x2a2a), 
    vector(0x4444, 0x4445, 0x4a4a)
  );
  event connection_state_remove(dummy);
}

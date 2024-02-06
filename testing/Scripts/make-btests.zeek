
# The event names the package hooks
global event_list: set[string] = set(
  "ssl_extension",
  "ssl_client_hello",
  "ssl_extension_server_name",
  "ssl_extension_supported_versions",
  "ssl_extension_signature_algorithm",
  "ssl_extension_application_layer_protocol_negotiation",
  "connection_state_remove"
);

event zeek_init() {
  print "# @TEST-EXEC: zeek $PACKAGE %INPUT >output";
  print "# @TEST-EXEC: cat ja4.log | zeek-cut ja4 o r ro grease_hash > ja4.filtered";
  print "# @TEST-EXEC: btest-diff ja4.filtered";
  print "# @TEST-EXEC: btest-diff output";
  print "";
  print "event zeek_init() {";
  print "  local dummy: connection = [";
  print "    $uid=\"UUIIDD\",";
  print "    $start_time=network_time(),";
  print "    $id=[";
  print "      $orig_h=1.1.1.1, $orig_p=1/tcp,";
  print "      $resp_h=2.2.2.2, $resp_p=2/tcp";
  print "    ],";
  print "    $orig=[$size=0, $state=0, $flow_label=0],";
  print "    $resp=[$size=0, $state=0, $flow_label=0],";
  print "    $duration=0msec,";
  print "    $service=set(\"SSL\"),";
  print "    $history=\"\"";
  print "  ];";
  print "";
}

event zeek_done() {
  print "}";
}

function trim_end(s: string, cruft: string &default=", "): string {
  if (ends_with(s, cruft)) {
    s = s[0:(-1 * |cruft|)];
  }
  return s;
}

# A function which handles the formatting of all argument types
#  passed to the above event list
function formatter(params: call_argument_vector): string {
  local s: string = "";
  local idx: count;
  for (idx in params) {
    local arg: call_argument = params[idx];
    if (!arg?$value) { next; }

    switch arg$type_name {
      case "connection":
        s += "dummy, ";
        break;

      case "string":
        local tmp_str: string = gsub(arg$value, /["]/, "\\\"");
        s += fmt("\"%s\", ", tmp_str);
        break;

      case "double":
        s += fmt("%s, ", floor(arg$value));
        break;

      case "time":
        s += fmt("%s, ", "network_time()");
        break;

      case "index_vec":
        local element_list: string = "";
        local i: count;
        local v = (arg$value as index_vec);
        for (i in v) {
          local element = v[i];
          element_list += fmt("%s, ", element);
        }
        element_list = trim_end(element_list);
        s += "vector(";
        s += fmt("%s), ", element_list);
        break;

      case "signature_and_hashalgorithm_vec":
        local e_list: string = "";
        local j: count;
        local sh_vec = (arg$value as signature_and_hashalgorithm_vec);
        for (j in sh_vec) {
          local sh: SSL::SignatureAndHashAlgorithm = sh_vec[j];
          e_list += fmt("[$HashAlgorithm=%s, $SignatureAlgorithm=%s], ",
            sh$HashAlgorithm,
            sh$SignatureAlgorithm
          );
        }
        e_list = trim_end(e_list);
        s += fmt("vector(%s), ", e_list);
        break;

      case "string_vec":
        local ele_list: string = "";
        local ja: count;
        local s_vec = (arg$value as string_vec);
        for (ja in s_vec) {
          local item: string = s_vec[ja];
          ele_list += fmt("\"%s\", ", item);
        }
        ele_list = trim_end(ele_list);
        s += fmt("vector(%s), ", ele_list);
        break;

      case "int", "bool", "count":
        s += fmt("%s, ", arg$value);
        break;

      default:
        s += fmt("%s, ", arg$value);
        break;
    }

  }
  s = trim_end(s);
  return s;
}

event new_event(name: string, params: call_argument_vector) {
  if (name !in event_list) { return; }
  print fmt("  event %s(%s);", name, formatter(params));
}

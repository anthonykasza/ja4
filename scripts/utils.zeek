
module JA4;

export {
  global is_valid_fqdn: function(s: string): bool;
}

# RFC 1035
function is_valid_fqdn(s: string): bool {

  # Trim all periods from ends
  while (ends_with(s, ".")) { s = s[0:-1]; }
  while (starts_with(s, ".")) { s = s[1:]; }

  local n: count = |s|;
  local idx: count;

  # Maximum character length excluding ending "."
  if (n > 254 || n == 0) { return F; }

  # cannot start or end with "-"
  if (s[0] == "-" || s[-1] == "-") { return F; }

  # str -> string_vec so we can iterate it using indexing
  local sv: string_vec = vector();
  local j: count = 0;
  for (char in s) {
    sv[j] = char;
    j += 1;
  }
  for (idx in sv) {
    # cannot contain any non-alphanumeric characters except "." and "-"
    if (!is_alnum(sv[idx]) && sv[idx] != "-" && sv[idx] != ".") { return F; }

    # cannot have 2 "-" in a row
    if (idx != n-1 && sv[idx] == "-" && sv[idx+1] == "-") { return F; }
  }

  # TODO: remove TLD before splitting by "." as some TLDs have "." in them
  #       for example, ".co.uk" is a TLD and should not count as 2 labels
  local labels: vector of string = split_string(s, /[.]/);

  # must have between 2 and 64 labels
  # TODO: this is affected by how TLDs are counted
  if (|labels| < 2 || |labels| > 63) { return F; }

  return T;
}

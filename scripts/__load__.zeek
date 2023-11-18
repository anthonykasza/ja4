module JA4;

export {
  # delimiter used to indicate different pieces of a fingerprint value
  option delimiter: string = "_";
  type Info: record {};
}
redef record connection += { ja4: JA4::Info &optional; };

@load ./ssl-consts
@load ./helpers
@load ./main

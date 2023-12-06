module JA4;

export {
	# delimiter used to indicate different pieces of a fingerprint value
	option delimiter: string = "_";

	# hash truncation length
	option hash_trunc_len: count = 12;
}

# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_done()
	{
	print JA4::delimiter;
	print JA4::hash_trunc_len;
	}

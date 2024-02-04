# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_done()
	{
	print JA4::TLS_VERSION_MAPPER;
	print JA4::TLS_GREASE_TYPES;
	}

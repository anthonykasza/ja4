# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output

print JA4::is_valid_fqdn("hello.com"), T;
print JA4::is_valid_fqdn("foo.hello.com"), T;
print JA4::is_valid_fqdn("hello.co.uk"), T;
print JA4::is_valid_fqdn("..hello.co.uk"), T;

print JA4::is_valid_fqdn("foo"), F;
print JA4::is_valid_fqdn(""), F;
print JA4::is_valid_fqdn("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), F;

print JA4::is_valid_fqdn("foo.localhost"), T;
print JA4::is_valid_fqdn("foo.foo"), T;

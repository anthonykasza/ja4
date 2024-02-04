@load ./config

module JA4;
export {
	type Info: record { };
}
redef record connection += {
	ja4: JA4::Info &optional;
};

@load ./constants
@load ./client-hello
@load ./main

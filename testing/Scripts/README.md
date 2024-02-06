*make-btests*, a script which prints a zeek btest using a template.
*iterate-pcaps*, a script which iterates over all files in the `testing/btest/Traces/tls` and `testing/btest/Traces/quic` directories of the zeek codebase. For each file, it uses `make-btests` to generate a testing script which does not require the original trace file.




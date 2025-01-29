score:
	zstd -d < trace/smalllinux-login-320576032.dromajo-trace.zst | cargo run --release --example parse_dromajo_trace|wc -l
	echo "expect 320576033"

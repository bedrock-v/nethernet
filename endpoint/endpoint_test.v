module endpoint

fn test_parse_burl_accepts_a_bare_origin_with_port() {
	assert parse_base_url('https://example.com:19132')! == 'https://example.com:19132'
	assert parse_base_url('http://127.0.0.1:27551')! == 'http://127.0.0.1:27551'
}

fn test_parse_base_url_trims_trailing_slash() {
	assert parse_base_url('https://example.com:19132/')! == 'https://example.com:19132'
}

fn test_parse_base_url_rejects_path() {
	if _ := parse_base_url('https://example.com:19132/v1/join') {
		assert false, 'a URL with a path should be rejected'
	}
}

fn test_parse_base_url_rejects_missing_port() {
	if _ := parse_base_url('https://example.com') {
		assert false, 'a URL with no explicit port should be rejected'
	}
}

fn test_parse_base_url_rejects_non_http_scheme() {
	if _ := parse_base_url('ws://example.com:19132') {
		assert false, 'a non-HTTP scheme should be rejected'
	}
}

fn test_all_digits() {
	assert all_digits('0')
	assert all_digits('123456789')
	assert !all_digits('')
	assert !all_digits('12a')
	assert !all_digits('-1')
}

fn test_conn_key_is_stable_for_the_same_pair() {
	assert connection_key('7', u64(9)) == connection_key('7', u64(9))
	assert connection_key('7', u64(9)) != connection_key('7', u64(10))
	assert connection_key('7', u64(9)) != connection_key('8', u64(9))
}

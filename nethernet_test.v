module nethernet

import crypto.ecdsa
import encoding.base64
import time

const sample_sdp = 'v=0\r\n' + 'o=- 1 2 IN IP4 127.0.0.1\r\n' + 's=-\r\n' + 't=0 0\r\n' +
	'a=group:BUNDLE 0\r\n' + 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n' +
	'c=IN IP4 0.0.0.0\r\n' + 'a=ice-ufrag:AbCd\r\n' + 'a=ice-pwd:0123456789abcdef0123\r\n' +
	'a=fingerprint:sha-256 AA:BB:CC:DD\r\n' + 'a=setup:actpass\r\n' + 'a=mid:0\r\n' +
	'a=sctp-port:5000\r\n' + 'a=max-message-size:262144\r\n'

fn test_signal_round_trip() {
	sig := Signal{
		typ:           signal_type_offer
		connection_id: 1234567890
		data:          'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n'
	}
	parsed := Signal.parse(sig.str())!

	assert parsed.typ == sig.typ
	assert parsed.connection_id == sig.connection_id
	assert parsed.data == sig.data
}

fn test_signal_parse_rejects_malformed_input() {
	if _ := Signal.parse('CANDIDATEADD') {
		assert false, 'a signal with no data was accepted'
	}
	if _ := Signal.parse('CANDIDATEADD notanumber candidate:1') {
		assert false, 'a signal with a non-numeric connection ID was accepted'
	}
}

fn test_format_ice_candidate_adds_the_extensions_the_game_expects() {
	line := 'candidate:1 1 udp 2130706431 192.168.1.2 50000 typ host'
	formatted := format_ice_candidate(3, line, 'AbCd')

	assert formatted.contains('generation 0')
	assert formatted.contains('ufrag AbCd')
	assert formatted.contains('network-id 3')
	assert formatted.contains('network-cost 0')
	assert formatted.starts_with('candidate:1 1 udp 2130706431 192.168.1.2 50000 typ host')
}

fn test_format_ice_candidate_keeps_the_related_address() {
	line := 'a=candidate:2 1 udp 1694498815 203.0.113.5 50001 typ srflx raddr 192.168.1.2 rport 50000'
	formatted := format_ice_candidate(0, line, 'ufragvalue')

	assert formatted.contains('raddr 192.168.1.2')
	assert formatted.contains('rport 50000')
	assert formatted.contains('ufrag ufragvalue')
}

fn test_description_attributes_are_read_from_the_right_scope() {
	assert media_attribute(sample_sdp, 'ice-ufrag')? == 'AbCd'
	assert media_attribute(sample_sdp, 'max-message-size')? == '262144'
	// ice-ufrag is a media attribute, so it must not be found at session scope.
	if _ := session_attribute(sample_sdp, 'ice-ufrag') {
		assert false, 'a media attribute was read as a session attribute'
	}
}

fn test_embed_candidates_writes_them_into_the_media_section() {
	embedded := embed_candidates(sample_sdp, [
		'candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host',
	])
	lines := embedded.split_into_lines()

	pwd_index := lines.index('a=ice-pwd:0123456789abcdef0123')
	candidate_index := lines.index('a=candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host')
	assert pwd_index >= 0
	assert candidate_index == pwd_index + 1
	assert description_candidates(embedded).len == 1
}

fn test_identity_assertion_round_trip() {
	private_key := ecdsa.PrivateKey.new(nid: .secp384r1)!
	identity := generate_server_identity(private_key, 'self')!

	signed := inject_identity(sample_sdp, identity.sign(sample_sdp)!)
	data := extract_identity(signed) or {
		assert false, 'the injected identity could not be read back'
		return
	}

	assert data.domain == 'self'
	assert data.protocol == 'default'
	assert data.valid()

	public_key := claim_public_key(data.token, true)!
	data.verify(signed, public_key)!
}

fn test_identity_assertion_does_not_verify_against_another_description() {
	private_key := ecdsa.PrivateKey.new(nid: .secp384r1)!
	identity := generate_server_identity(private_key, 'self')!
	signed := inject_identity(sample_sdp, identity.sign(sample_sdp)!)

	data := extract_identity(signed) or {
		assert false, 'the injected identity could not be read back'
		return
	}
	public_key := claim_public_key(data.token, true)!

	// A different DTLS certificate means different fingerprints, which is what
	// stops an assertion from being replayed onto another connection.
	other := sample_sdp.replace('AA:BB:CC:DD', '11:22:33:44')
	if _ := data.verify(other, public_key) {
		assert false, 'the assertion verified against a description it did not sign'
	}
}

fn test_self_signed_token_must_be_signed_by_the_key_it_claims() {
	private_key := ecdsa.PrivateKey.new(nid: .secp384r1)!
	identity := generate_server_identity(private_key, 'self')!

	mut segments := identity.token.split('.')
	// Corrupt the signature without touching the claims.
	segments[2] = base64url_encode([]u8{len: 96, init: u8(index)})
	if _ := claim_public_key(segments.join('.'), true) {
		assert false, 'a token with a broken signature was accepted'
	}
}

fn test_reissued_token_keeps_the_key_and_is_still_valid() {
	private_key := ecdsa.PrivateKey.new(nid: .secp384r1)!
	identity := generate_server_identity(private_key, 'self')!
	reissued := identity.reissue()!

	assert reissued.domain == identity.domain
	// The key is what a client remembers the server by, so reissuing must not
	// change it - only the token's lifetime moves.
	public_key := claim_public_key(reissued.token, true)!
	assert public_key.equal(claim_public_key(identity.token, true)!)
	assert token_expiry(reissued.token)! > time.now().unix()

	signed := inject_identity(sample_sdp, reissued.sign(sample_sdp)!)
	data := extract_identity(signed) or {
		assert false, 'the reissued identity could not be read back'
		return
	}
	data.verify(signed, public_key)!
}

fn token_expiry(token string) !i64 {
	claims := parse_token_claims(base64url_decode(token.split('.')[1])!)!
	return claims.expires_at
}

fn test_public_key_encoding_round_trip() {
	private_key := ecdsa.PrivateKey.new(nid: .secp384r1)!
	public_key := private_key.public_key()!

	der := encode_public_key(public_key)!
	decoded := decode_public_key(der)!
	assert decoded.equal(public_key)
}

fn test_der_and_raw_signatures_convert_both_ways() {
	private_key := ecdsa.PrivateKey.new(nid: .secp384r1)!
	der := private_key.sign('payload'.bytes())!

	raw := der_signature_to_raw(der, 48)!
	assert raw.len == 96

	public_key := private_key.public_key()!
	assert public_key.verify('payload'.bytes(), raw_signature_to_der(raw)!)!
}

fn test_messages_reassemble_from_segments() {
	mut conn := &Conn{}
	// Three segments of one message: the counter names how many are still to
	// come, so only the last one completes it.
	_, first := conn.accept_segment(.reliable, [u8(2), `a`])!
	assert !first
	_, second := conn.accept_segment(.reliable, [u8(1), `b`])!
	assert !second
	payload, complete := conn.accept_segment(.reliable, [u8(0), `c`])!
	assert complete
	assert payload == 'abc'.bytes()
}

fn test_out_of_sequence_segments_are_rejected() {
	mut conn := &Conn{}
	conn.accept_segment(.reliable, [u8(3), `a`])!
	if _, _ := conn.accept_segment(.reliable, [u8(1), `b`]) {
		assert false, 'a segment that skipped the sequence was accepted'
	}
}

fn test_unreliable_channel_refuses_segmented_messages() {
	mut conn := &Conn{}
	if _, _ := conn.accept_segment(.unreliable, [u8(1), `a`]) {
		assert false, 'a segmented message was accepted on the unreliable channel'
	}
}

fn test_data_channel_parameters_match_the_game() {
	assert MessageReliability.reliable.label() == 'ReliableDataChannel'
	assert MessageReliability.unreliable.label() == 'UnreliableDataChannel'
	assert MessageReliability.reliable.options().ordered
	assert MessageReliability.unreliable.options().max_retransmits? == 0
}

// A peer that writes the attribute into its media section still means it. The
// game's own client does, and a description carries no second `a=identity` to
// confuse it with.
fn test_identity_assertion_is_read_below_the_media_section() {
	private_key := ecdsa.PrivateKey.new(nid: .secp384r1)!
	identity := generate_server_identity(private_key, 'self')!
	signed := inject_identity(sample_sdp, identity.sign(sample_sdp)!)

	mut attribute := ''
	mut without := []string{}
	for line in signed.split_into_lines() {
		if line.starts_with('a=identity:') {
			attribute = line
			continue
		}
		if line != '' {
			without << line
		}
	}
	assert attribute != ''
	below := without.join('\r\n') + '\r\n' + attribute + '\r\n'

	data := extract_identity(below) or {
		assert false, 'an identity below the media section was not read'
		return
	}
	assert data.domain == 'self'
	assert data.valid()
}

// The assertion travels as a JSON object inside a JSON string. An
// implementation that nests it directly is read the same way.
fn test_identity_assertion_accepts_a_nested_assertion() {
	private_key := ecdsa.PrivateKey.new(nid: .secp384r1)!
	identity := generate_server_identity(private_key, 'self')!
	data := identity.sign(sample_sdp)!

	nested := base64.encode('{"assertion":{"fingerprints":${json_string(data.fingerprints)},"token":${json_string(data.token)}},"idp":{"domain":"self","protocol":"default"}}'.bytes())
	read := extract_identity('${sample_sdp}a=identity:${nested}\r\n') or {
		assert false, 'a nested assertion was not read'
		return
	}
	assert read.token == data.token
	assert read.fingerprints == data.fingerprints
	assert read.valid()
}

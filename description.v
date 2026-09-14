module nethernet

import encoding.base64
import x.json2

// NetherNet's SDP is ordinary WebRTC data-channel SDP with one addition: a
// session-level `a=identity` attribute carrying the identity assertion. The
// WebRTC stack neither writes nor reads it, so it is spliced into the text on
// the way out and picked back out on the way in.

// max_message_size is the largest payload one data channel message may carry.
//
// Vanilla advertises 262144 in `a=max-message-size` and reserves the first byte
// of every message for the segment counter, leaving this for the payload.
pub const max_message_size = 262143

// sctp_message_size is how large a single data channel message is actually
// written, counter byte included.
//
// It is far below what the description advertises on purpose: the game's own
// stack writes messages of this size, and an SCTP implementation is free to
// refuse anything larger than it is prepared to reassemble whatever the
// negotiated maximum says. Sending one big message where vanilla sends many
// small ones is the kind of difference a peer notices.
pub const sctp_message_size = 10000

// max_segment_payload is what one segment carries once the counter byte is
// taken off the front.
pub const max_segment_payload = sctp_message_size - 1

// inject_identity adds the identity assertion to a local description.
//
// It goes ahead of the first media section: `a=identity` is a session-level
// attribute, and anything after an `m=` line belongs to that section instead.
fn inject_identity(sdp_text string, data IdentityData) string {
	assertion := '{"fingerprints":${json_string(data.fingerprints)},"token":${json_string(data.token)}}'
	encoded :=
		base64.encode('{"assertion":${json_string(assertion)},"idp":{"domain":${json_string(data.domain)},"protocol":${json_string(data.protocol)}}}'.bytes())
	attribute := 'a=identity:${encoded}'

	mut lines := []string{}
	mut inserted := false
	for line in sdp_text.split_into_lines() {
		if !inserted && line.starts_with('m=') {
			lines << attribute
			inserted = true
		}
		lines << line
	}
	if !inserted {
		lines << attribute
	}
	// SDP lines are CRLF-terminated, including the last one.
	return lines.filter(it != '').join('\r\n') + '\r\n'
}

// extract_identity reads the identity assertion out of a remote description.
// It returns none when the peer sent none, which is what an offline or custom
// implementation does.
fn extract_identity(sdp_text string) ?IdentityData {
	// The attribute belongs at session level and is written there, but it is
	// read from anywhere in the description: a peer that places it after its
	// first media section still means it, and no other attribute of this name
	// exists to confuse it with.
	encoded := media_attribute(sdp_text, 'identity')?
	decoded := base64.decode(encoded)
	if decoded.len == 0 {
		return none
	}
	outer := json2.decode[json2.Any](decoded.bytestr()) or { return none }.as_map()

	assertion := decode_assertion(outer['assertion'] or { return none })?
	idp := outer['idp'] or { return none }.as_map()

	data := IdentityData{
		fingerprints: assertion['fingerprints'] or { return none }.str()
		token:        assertion['token'] or { return none }.str()
		domain:       if value := idp['domain'] { value.str() } else { '' }
		protocol:     if value := idp['protocol'] { value.str() } else { '' }
	}
	if !data.valid() {
		return none
	}
	return data
}

// decode_assertion reads the inner assertion. The game encodes it as a JSON
// object inside a JSON string, so it is decoded twice; an implementation that
// nests it as an object instead is read as it stands.
fn decode_assertion(value json2.Any) ?map[string]json2.Any {
	if value is map[string]json2.Any {
		return value
	}
	return json2.decode[json2.Any](value.str()) or { return none }.as_map()
}

// session_attribute returns the value of a session-level attribute: one that
// appears before the first media section.
fn session_attribute(sdp_text string, key string) ?string {
	prefix := 'a=${key}:'
	for line in sdp_text.split_into_lines() {
		trimmed := line.trim_space()
		if trimmed.starts_with('m=') {
			break
		}
		if trimmed.starts_with(prefix) {
			return trimmed[prefix.len..]
		}
	}
	return none
}

// media_attribute returns the value of the first attribute with this key
// anywhere in the description. The connection is bundled onto one transport, so
// a value repeated across sections is the same value.
fn media_attribute(sdp_text string, key string) ?string {
	prefix := 'a=${key}:'
	for line in sdp_text.split_into_lines() {
		trimmed := line.trim_space()
		if trimmed.starts_with(prefix) {
			return trimmed[prefix.len..]
		}
	}
	return none
}

// description_candidates returns the candidate lines embedded in a description.
// A peer that cannot trickle sends them this way instead.
fn description_candidates(sdp_text string) []string {
	mut out := []string{}
	for line in sdp_text.split_into_lines() {
		trimmed := line.trim_space()
		if trimmed.starts_with('a=candidate:') {
			out << trimmed[2..]
		}
	}
	return out
}

// embed_candidates writes candidate lines into the media section of a local
// description, for a peer that cannot accept them separately.
fn embed_candidates(sdp_text string, candidates []string) string {
	if candidates.len == 0 {
		return sdp_text
	}

	mut lines := []string{}
	mut seen_media := false
	mut inserted := false
	for line in sdp_text.split_into_lines() {
		if line == '' {
			continue
		}
		if line.starts_with('m=') {
			seen_media = true
		}
		// The candidates go directly after the ICE credentials they belong to,
		// which is where a peer expects to find them.
		if seen_media && !inserted && line.starts_with('a=ice-pwd:') {
			lines << line
			for candidate in candidates {
				lines << 'a=${candidate}'
			}
			inserted = true
			continue
		}
		lines << line
	}
	if !inserted {
		for candidate in candidates {
			lines << 'a=${candidate}'
		}
	}
	return lines.join('\r\n') + '\r\n'
}

// json_string quotes and escapes a string for the hand-built JSON above.
fn json_string(value string) string {
	mut out := '"'
	for c in value {
		match c {
			`"` { out += '\\"' }
			`\\` { out += '\\\\' }
			`\n` { out += '\\n' }
			`\r` { out += '\\r' }
			`\t` { out += '\\t' }
			else { out += if c < 0x20 { '\\u${c:04x}' } else { c.ascii_str() } }
		}
	}
	return out + '"'
}

// candidate_address is the connection address of a candidate line, or none when
// it carries none.
//
// RFC 5245 section 15.1 puts it in the fifth token, after the foundation, the
// component, the transport and the priority.
fn candidate_address(candidate string) ?string {
	fields := candidate_fields(candidate)
	if fields.len < 5 {
		return none
	}
	return fields[4]
}

// candidate_fields splits a candidate line into its tokens, with the `a=` and
// `candidate:` prefixes taken off whichever way it was written.
fn candidate_fields(candidate string) []string {
	mut body := candidate.trim_space()
	if body.starts_with('a=') {
		body = body[2..]
	}
	if body.starts_with('candidate:') {
		body = body['candidate:'.len..]
	}
	return body.split(' ').filter(it != '')
}

// inferred_candidate_limit bounds how many ports are guessed at for one peer.
//
// A peer gathers one port per interface it holds, so a handful covers any real
// client. How many packets leave here is not something the peer should get to
// decide by sending a long offer.
const inferred_candidate_limit = 8

// inferred_peer_candidates builds candidates for the address a peer signalled
// from, one per port it gathered locally.
//
// A peer holding no reflexive candidate offers nothing a host on another
// network can reach, and its own checks die on the first NAT they meet. Its
// public address is known anyway, because it just sent a signal from it, and
// consumer NATs usually keep the port a socket already uses. Checking there
// costs a few packets, and if the mapping does work that way the check opens
// the path in both directions.
//
// Nothing is inferred for a peer that already carries a reflexive or relayed
// candidate, or that signalled from an address on this network: there is a real
// path in both cases.
fn inferred_peer_candidates(sdp_text string, signaled_from string) []string {
	host, _ := split_host_port(signaled_from) or { return []string{} }
	if !is_routable(host) {
		return []string{}
	}

	mut ports := []string{}
	for line in sdp_text.split_into_lines() {
		trimmed := line.trim_space()
		if !trimmed.starts_with('a=candidate:') {
			continue
		}
		fields := candidate_fields(trimmed)
		if fields.len < 8 || fields[6] != 'typ' {
			continue
		}
		if fields[7] != 'host' {
			// The peer can already be reached without guessing.
			return []string{}
		}
		if fields[2].to_lower() == 'udp' && ports.len < inferred_candidate_limit
			&& fields[5] !in ports {
			ports << fields[5]
		}
	}

	mut out := []string{cap: ports.len}
	mut foundation := 90000000
	for port in ports {
		out << 'candidate:${foundation} 1 UDP 1677721855 ${host} ${port} typ srflx raddr 0.0.0.0 rport 0'
		foundation++
	}
	return out
}

// filter_candidates drops every candidate whose address is not in allowed.
//
// ICE gathers on every interface it can see, which on a host running containers
// or an overlay network includes addresses nothing outside can reach. Each one
// costs the peer a round of connectivity checks before it gives up, so a host
// that knows which of its addresses are reachable should announce only those.
//
// An empty set announces everything. So does a set that would leave nothing at
// all: no candidates can never connect, and a misconfigured list should not be
// the reason a server is unreachable.
fn filter_candidates(sdp_text string, allowed []string) string {
	if allowed.len == 0 {
		return sdp_text
	}
	mut keys := []string{cap: allowed.len}
	for address in allowed {
		keys << address_key(address.trim_space())
	}

	mut lines := []string{}
	mut kept := false
	mut dropped := false
	for line in sdp_text.split_into_lines() {
		// A trailing empty line makes some stacks reject the whole description.
		if line == '' {
			continue
		}
		if line.trim_space().starts_with('a=candidate:') {
			address := candidate_address(line) or {
				dropped = true
				continue
			}
			if address_key(address) !in keys {
				dropped = true
				continue
			}
			kept = true
		}
		lines << line
	}
	if !kept && dropped {
		return sdp_text
	}
	return lines.join('\r\n') + '\r\n'
}

// candidate_allowed reports whether a single candidate line may be announced,
// for the trickled candidates that never pass through filter_candidates.
fn candidate_allowed(candidate string, allowed []string) bool {
	if allowed.len == 0 {
		return true
	}
	address := candidate_address(candidate) or { return false }
	key := address_key(address)
	for entry in allowed {
		if address_key(entry.trim_space()) == key {
			return true
		}
	}
	return false
}

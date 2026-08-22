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

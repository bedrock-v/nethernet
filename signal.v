// Package nethernet implements the NetherNet transport used by Minecraft:
// Bedrock Edition.
//
// NetherNet carries the game protocol over a WebRTC peer connection. Two
// endpoints exchange SDP offers and answers, plus ICE candidates, over an
// out-of-band signalling channel - a LAN broadcast on the local network, or a
// WebSocket to a Microsoft service. Once the peer connection is up, game
// packets travel over two data channels named "ReliableDataChannel" and
// "UnreliableDataChannel".
module nethernet

// Signal types exchanged over signalling to negotiate a connection.
pub const signal_type_offer = 'CONNECTREQUEST'

pub const signal_type_answer = 'CONNECTRESPONSE'

pub const signal_type_candidate = 'CANDIDATEADD'

pub const signal_type_error = 'CONNECTERROR'

// Signal is one message exchanged over signalling to negotiate a connection.
//
// The wire form is `<type> <connection id> <data>`; the network ID is not part
// of it, because the signalling channel already knows which network a message
// came from or is going to.
pub struct Signal {
pub mut:
	// typ is one of the signal_type_* constants.
	typ string
	// connection_id uniquely references one connection between two networks. It
	// is chosen by the client and reused by the server in its replies.
	connection_id u64
	// data is the payload: an SDP description, a candidate line, or an error
	// code, depending on typ.
	data string
	// network_id is the remote network this signal came from or is going to. It
	// is carried alongside the signal rather than inside it.
	network_id string
}

// str renders the signal in the form it is sent over signalling.
pub fn (s Signal) str() string {
	return '${s.typ} ${s.connection_id} ${s.data}'
}

// Signal.parse decodes a signal from its wire form. The network ID is left
// empty; the caller fills it in from the signalling channel.
pub fn Signal.parse(text string) !Signal {
	segments := text.split_nth(' ', 3)
	if segments.len != 3 {
		return error('nethernet: signal has ${segments.len} segments, expected 3')
	}
	connection_id := segments[1].u64()
	if connection_id == 0 && segments[1] != '0' {
		return error('nethernet: invalid connection ID "${segments[1]}"')
	}
	return Signal{
		typ:           segments[0]
		connection_id: connection_id
		data:          segments[2]
	}
}

// Error codes carried in the data of a signal_type_error signal. They mirror
// the values the game itself reports, so a vanilla peer can make sense of them.
pub const error_code_none = 0

pub const error_code_destination_not_logged_in = 1

pub const error_code_negotiation_timeout = 2

pub const error_code_wrong_transport_version = 3

pub const error_code_failed_to_create_peer_connection = 4

pub const error_code_ice = 5

pub const error_code_connect_request = 6

pub const error_code_connect_response = 7

pub const error_code_candidate_add = 8

pub const error_code_inactivity_timeout = 9

pub const error_code_failed_to_create_offer = 10

pub const error_code_failed_to_create_answer = 11

pub const error_code_failed_to_set_local_description = 12

pub const error_code_failed_to_set_remote_description = 13

pub const error_code_negotiation_timeout_waiting_for_response = 14

pub const error_code_negotiation_timeout_waiting_for_accept = 15

pub const error_code_incoming_connection_ignored = 16

pub const error_code_signaling_parsing_failure = 17

pub const error_code_signaling_unknown_error = 18

pub const error_code_signaling_unicast_message_delivery_failed = 19

pub const error_code_signaling_broadcast_delivery_failed = 20

pub const error_code_signaling_message_delivery_failed = 21

pub const error_code_signaling_turn_auth_failed = 22

pub const error_code_signaling_fallback_to_best_effort_delivery = 23

pub const error_code_no_signaling_channel = 24

pub const error_code_not_logged_in = 25

pub const error_code_signaling_failed_to_send = 26

pub const error_code_data_channel_closed = 32

pub const error_code_invalid_argument = 34

pub const error_code_generic_failure = 35

// error_code_identity_verification_failed reports that the remote identity
// token, or its DTLS fingerprint assertion, failed validation.
pub const error_code_identity_verification_failed = 37

// format_ice_candidate rewrites a candidate line into the form the C++ WebRTC
// implementation produces.
//
// The game's parser expects the `generation`, `ufrag`, `network-id` and
// `network-cost` extensions and ignores candidates without them, so a candidate
// gathered locally has to be reformatted before it is signalled.
fn format_ice_candidate(id int, line string, ufrag string) string {
	mut body := line.trim_space()
	if body.starts_with('a=') {
		body = body[2..]
	}
	if body.starts_with('candidate:') {
		body = body['candidate:'.len..]
	}
	fields := body.split(' ').filter(it != '')
	if fields.len < 8 {
		return 'candidate:${body}'
	}

	mut parts := fields[..8].clone()
	// The related address is diagnostic, but the game echoes it back, so a
	// reflexive or relayed candidate keeps it.
	for i := 8; i + 1 < fields.len; i += 2 {
		if fields[i] == 'raddr' || fields[i] == 'rport' {
			parts << fields[i]
			parts << fields[i + 1]
		}
	}
	parts << ['generation', '0', 'ufrag', ufrag, 'network-id', id.str(), 'network-cost', '0']
	return 'candidate:${parts.join(' ')}'
}

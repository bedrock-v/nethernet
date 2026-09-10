module nethernet

import bedrock_v.webrtc

// Structured observation of a connection as it is established.
//
// This exists for research and diagnostic tooling. It reports what happened; it
// owns no protocol state, is never consulted for a decision and a connection
// behaves the same whether or not anything is listening.

// ChannelObservation is what one data channel looked like as a connection took
// it.
//
// It is a snapshot taken at that moment. Nothing here is read again afterwards,
// so a recorder may keep it without holding anything belonging to the
// connection alive.
pub struct ChannelObservation {
pub:
	// connection_id is the id both ends use to reference this connection in
	// every signal exchanged for it and network_id names the remote network.
	//
	// A listener negotiates each offer in its own thread and hands them all the
	// same callback, so observations from different connections arrive
	// interleaved. Without these, a recorder cannot tell which connection a
	// channel belonged to and the per connection results it produces are
	// wrong in a way nothing reveals.
	//
	// The client chooses connection_id, a listener should treat it as a
	// label rather than a guarantee: two peers may pick the same one and a
	// hostile peer may pick another's on purpose.
	connection_id u64
	network_id    string
	label         string
	ordered    bool
	reliable   bool
	negotiated bool
	protocol   string
	// id is the SCTP stream the channel runs on and none while the transports
	// have not assigned one.
	id ?u16
	// opened_locally separates the channel this side created from the one the
	// peer opened and this side adopted. Which side opens which is a NetherNet
	// rule rather than a WebRTC one.
	opened_locally bool
	// reliability is which of the two NetherNet channels this was taken as and
	// none when it matched neither.
	//
	// That last case is the one worth recording. A channel this end refuses is
	// otherwise visible only as an error message and what an unrecognised peer
	// actually opened is exactly what a reader of that error wants to know.
	reliability ?MessageReliability
}

// ObserveChannel is called once for each data channel a connection takes.
//
// It runs on the thread establishing the connection and a listener runs one of
// those per offer, so the same callback is called from several threads at once
// and has to be safe for that.
//
// It must not block: a callback that waits there delays, and can fail, the
// handshake it is watching. It must not panic either. V can't recover from
// one, so a panic here takes the connection's thread with it.
pub type ObserveChannel = fn (ChannelObservation)

// observe_channel reports a channel to the callback if there's one.
fn observe_channel(callback ?ObserveChannel, connection_id u64, network_id string, mut channel webrtc.DataChannel, opened_locally bool, reliability ?MessageReliability) {
	report := callback or { return }
	report(ChannelObservation{
		connection_id:  connection_id
		network_id:     network_id
		label:          channel.label
		ordered:        channel.ordered()
		reliable:       channel.reliable()
		negotiated:     channel.negotiated()
		protocol:       channel.protocol()
		id:             channel.id()
		opened_locally: opened_locally
		reliability:    reliability
	})
}

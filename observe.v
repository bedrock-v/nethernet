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
	label      string
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
// It runs on the thread establishing the connection.
pub type ObserveChannel = fn (ChannelObservation)

// observe_channel reports a channel to the callback if there's one.
fn observe_channel(callback ?ObserveChannel, mut channel webrtc.DataChannel, opened_locally bool, reliability ?MessageReliability) {
	report := callback or { return }
	report(ChannelObservation{
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

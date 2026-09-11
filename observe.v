module nethernet

import bedrock_v.webrtc
import sync.stdatomic

// Structured observation of a connection as it is established.
//
// This exists for research and diagnostic tooling. It reports what happened,
// owns no protocol state and is never consulted for a decision.
//
// The observer's own code never runs on the path that establishes a
// connection. nethernet builds each snapshot itself and hands it over with a
// send that doesn't wait, so an observer that reads slowly, or not at all,
// loses observations.

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
	// same observer, so observations from different connections arrive
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
	ordered       bool
	reliable      bool
	negotiated    bool
	protocol      string
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

// ChannelObserver receives channel observations without its reader being able
// to reach the connection that produced them.
//
// Observations wait in a bounded channel that the reader drains in its own
// time. A listener shares one observer across every connection it negotiates
// and a connection offers only a few: two when dialling and when listening two
// plus the one it may refuse. Size the channel for the connections expected to
// be established between reads.
@[heap]
pub struct ChannelObserver {
pub:
	observations chan ChannelObservation
mut:
	// dropped is kept with atomics rather than a lock, a full channel costs
	// the connection an increment and nothing it could wait on.
	dropped u64
}

// ChannelObserver.new returns an observer whose channel holds capacity
// observations. An unbuffered channel would drop every observation made while
// no reader was waiting, which is nearly all of them, so capacity must be
// positive.
pub fn ChannelObserver.new(capacity int) !&ChannelObserver {
	if capacity < 1 {
		return error('nethernet: an observer needs room for at least one observation, got ${capacity}')
	}
	return &ChannelObserver{
		observations: chan ChannelObservation{cap: capacity}
	}
}

// dropped is how many observations were discarded because the channel was
// full. A set of observations is only complete when this is zero.
pub fn (o &ChannelObserver) dropped() u64 {
	return stdatomic.load_u64(&o.dropped)
}

// offer hands an observation over without waiting. A full channel costs the
// observation.
//
// The receiver is not mut. One observer is shared by every connection a
// listener negotiates, so it is written from several threads regardless and
// its only write is the atomic increment below which a mut receiver would
// make no safer.
fn (o &ChannelObserver) offer(observation ChannelObservation) {
	select {
		o.observations <- observation {}
		else {
			stdatomic.add_u64(&o.dropped, 1)
		}
	}
}

// observe_channel snapshots a channel and offers it to the observer,
// if there's one.
fn observe_channel(observer ?&ChannelObserver, connection_id u64, network_id string, mut channel webrtc.DataChannel, opened_locally bool, reliability ?MessageReliability) {
	target := observer or { return }
	target.offer(ChannelObservation{
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

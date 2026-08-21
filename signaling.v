module nethernet

// Signaling is the out-of-band channel two networks use to exchange signals
// before a peer connection exists.
//
// The transport is not part of NetherNet itself: a LAN game broadcasts on UDP
// port 7551, while an online game uses a WebSocket to a Microsoft service. Both
// carry the same signals, so a Dialer or a Listener works with either.
pub interface Signaling {
	// network_id is the local network ID of this signalling channel. A Listener
	// announces it, and a Dialer names the remote one it wants to reach.
	network_id() string
	// disable_trickle_ice reports whether the channel can carry candidates after
	// the initial description. Dedicated servers with the
	// `nethernet-disable-trickle-ice` setting, including Realms, cannot: every
	// local candidate has to be gathered up front and embedded in the SDP.
	disable_trickle_ice() bool
mut:
	// signal sends a signal to the network named by Signal.network_id.
	signal(sig Signal) !
	// notify registers n for incoming signals and returns a subscription ID that
	// stop_notify takes. Every subscription receives every signal; they are not
	// load-balanced.
	notify(n Notifier) int
	// stop_notify cancels a subscription. It must tolerate being called more
	// than once with the same ID.
	stop_notify(id int)
	// credentials returns the ICE servers to gather through. A channel that
	// hands none out - a LAN, where every peer is directly reachable - returns
	// an empty set rather than failing.
	credentials() !Credentials
	// pong_data sets the server data to answer discovery requests with, in the
	// format of a RakNet pong response.
	pong_data(data []u8)
	// is_closed reports whether the channel has stopped carrying signals. A
	// Dialer or Listener gives up once it does.
	is_closed() bool
}

// Notifier receives signals from a Signaling implementation.
pub interface Notifier {
mut:
	// notify_signal handles one incoming signal and reports whether it was
	// accepted. It must return promptly: the signalling channel calls it from
	// its own read loop.
	notify_signal(sig Signal) bool
}

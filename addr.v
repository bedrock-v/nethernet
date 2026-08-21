module nethernet

// Addr names one end of a NetherNet connection.
//
// There is no IP address here on purpose: a network ID identifies a peer across
// whatever path ICE happens to pick, and the path may change while the
// connection lives. The candidates are carried alongside for diagnostics.
pub struct Addr {
pub mut:
	// connection_id is the identifier the client chose for this connection. It
	// is zero for a listener's own address, which is not tied to a connection.
	connection_id u64
	// network_id identifies the NetherNet network.
	network_id string
	// candidates are the ICE candidate lines gathered locally or signalled by
	// the peer.
	candidates []string
	// selected_candidate is the candidate line ICE settled on, when there is
	// one.
	selected_candidate string
}

// network is always "nethernet".
pub fn (a &Addr) network() string {
	return 'nethernet'
}

// str renders the address for a log line: the network, the connection, and the
// path ICE settled on, when there is one.
pub fn (a &Addr) str() string {
	mut out := a.network_id
	if a.connection_id != 0 {
		out += ' (${a.connection_id})'
	}
	if a.selected_candidate != '' {
		out += ' (${a.selected_candidate})'
	}
	return out
}

// key identifies a connection between two networks. A listener uses it to route
// an incoming signal to the connection it belongs to.
fn (a &Addr) key() string {
	return '${a.network_id}/${a.connection_id}'
}

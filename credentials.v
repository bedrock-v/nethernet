module nethernet

import webrtc

// Credentials are the ICE servers a signalling service hands out for gathering
// local candidates. They expire, which is why they are fetched per connection
// rather than configured once.
pub struct Credentials {
pub:
	expiration_in_seconds int
	ice_servers           []IceServer
}

// IceServer is one STUN or TURN server, with the long-term credentials a relay
// needs.
pub struct IceServer {
pub:
	username string
	password string
	urls     []string
}

// to_webrtc converts the servers into the shape the WebRTC stack takes.
fn (c &Credentials) to_webrtc() []webrtc.IceServer {
	mut servers := []webrtc.IceServer{cap: c.ice_servers.len}
	for server in c.ice_servers {
		servers << webrtc.IceServer{
			urls:       server.urls
			username:   server.username
			credential: server.password
		}
	}
	return servers
}

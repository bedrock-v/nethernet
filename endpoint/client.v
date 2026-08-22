module endpoint

import net.http
import rand
import sync
import time
import nethernet
import webrtc.logging

// ClientConfig configures an EndpointClient.
@[params]
pub struct ClientConfig {
pub:
	// network_id identifies this client in the URL path of every request it
	// sends. Empty picks a random one which is what a client normally wants.
	// This has nothing to do with the base URL passed to nethernet.dial - see
	// EndpointClient's own doc comment.
	network_id string
	// credentials overrides the ICE servers handed out for gathering local
	// candidates. Unset returns none, the same as a LAN signalling channel.
	credentials ?nethernet.Credentials
	// read_timeout bounds how long a POST /v1/join/{id} request waits for the
	// server's answer.
	read_timeout time.Duration  = 30 * time.second
	logger       logging.Logger = logging.nop()
}

// EndpointClient is the dialling side of HTTP signalling: an
// nethernet.Signaling implementation that reaches a server directly by
// address rather than through LAN broadcast or Xbox Live.
//
// Pass it to nethernet.dial with the server's base URL.
pub struct EndpointClient {
mut:
	config ClientConfig
	log    logging.Logger

	notifiers    map[int]nethernet.Notifier
	notify_count int
	notifiers_mu &sync.Mutex = sync.new_mutex()
pub:
	network_id string
}

// client creates an EndpointClient.
pub fn client(config ClientConfig) &EndpointClient {
	mut network_id := config.network_id
	if network_id == '' {
		network_id = rand.u64().str()
	}
	return &EndpointClient{
		config:     config
		log:        config.logger.with_scope('nethernet/endpoint')
		network_id: network_id
	}
}

pub fn (c &EndpointClient) network_id() string {
	return c.network_id
}

// disable_trickle_ice always returns true: an HTTP request/response round
// trip can't carry a candidate after the answer has already come back.
pub fn (c &EndpointClient) disable_trickle_ice() bool {
	return true
}

pub fn (mut c EndpointClient) credentials() !nethernet.Credentials {
	return c.config.credentials or { nethernet.Credentials{} }
}

// pong_data has nothing to set: an EndpointClient only dials out and never
// answers a discovery style ping.
pub fn (mut c EndpointClient) pong_data(data []u8) {}

// is_closed always reports false: an EndpointClient has no connection of its
// own to lose. Every request opens and closes independently.
pub fn (mut c EndpointClient) is_closed() bool {
	return false
}

pub fn (mut c EndpointClient) notify(n nethernet.Notifier) int {
	c.notifiers_mu.lock()
	defer {
		c.notifiers_mu.unlock()
	}
	id := c.notify_count
	c.notifiers[id] = n
	c.notify_count++
	return id
}

pub fn (mut c EndpointClient) stop_notify(id int) {
	c.notifiers_mu.lock()
	c.notifiers.delete(id)
	c.notifiers_mu.unlock()
}

// signal sends sig to the server the network ID names.
// Only an offer is ever actually sent over the wire:
// the answer comes back as this same request's response
// and is delivered locally through notify, and an error
// signal has nowhere further to go once the dial has
// already failed.
pub fn (mut c EndpointClient) signal(sig nethernet.Signal) ! {
	match sig.typ {
		nethernet.signal_type_offer {
			c.send_offer(sig)!
		}
		nethernet.signal_type_error {}
		nethernet.signal_type_candidate {
			return error('nethernet/endpoint: trickle ICE is not supported')
		}
		else {
			return error('nethernet/endpoint: unknown signal type "${sig.typ}"')
		}
	}
}

// send_offer POSTs the offer to the server's /v1/join/{network_id} endpoint
// and delivers the resulting answer to every registered notifier.
fn (mut c EndpointClient) send_offer(sig nethernet.Signal) ! {
	base := parse_base_url(sig.network_id)!
	url := '${base}/v1/join/${c.network_id}'

	resp := http.fetch(
		url:          url
		method:       .post
		data:         sig.data
		header:       http.new_header(http.HeaderConfig{
			key:   .content_type
			value: 'application/sdp'
		})
		user_agent:   'libhttpclient/1.0.0.0'
		read_timeout: i64(c.config.read_timeout)
	) or { return error('nethernet/endpoint: POST ${url}: ${err.msg()}') }

	if resp.status_code != 200 {
		return error('nethernet/endpoint: POST ${url}: ${resp.status_code} ${resp.status_msg}')
	}
	body := resp.body
	if body.len == 0 {
		return error('nethernet/endpoint: missing SDP answer in response body')
	}
	if body.len > max_sdp_body_size {
		return error('nethernet/endpoint: SDP answer exceeds ${max_sdp_body_size} bytes')
	}
	trimmed := body.trim_space()
	if all_digits(trimmed) {
		return error('nethernet/endpoint: negotiation failed with error code: ${trimmed}')
	}

	c.notify_signal(nethernet.Signal{
		typ:           nethernet.signal_type_answer
		connection_id: sig.connection_id
		data:          body
		network_id:    sig.network_id
	})
}

// notify_signal broadcasts sig to every Dialer subscribed to this client.
fn (mut c EndpointClient) notify_signal(sig nethernet.Signal) {
	c.notifiers_mu.lock()
	mut notifiers := []nethernet.Notifier{cap: c.notifiers.len}
	for _, n in c.notifiers {
		notifiers << n
	}
	c.notifiers_mu.unlock()
	for mut n in notifiers {
		n.notify_signal(sig)
	}
}

// parse_base_url validates that raw is the shape this transport dials: an
// http or https origin, no path with an explicit port.
fn parse_base_url(raw string) !string {
	invalid := 'nethernet/endpoint: network ID must be a HTTP/HTTPS URL with port: ${raw}'
	if !raw.starts_with('http://') && !raw.starts_with('https://') {
		return error(invalid)
	}
	trimmed := raw.trim_right('/')
	rest := trimmed.all_after('://')
	if rest.contains('/') {
		return error(invalid)
	}
	if !rest.contains(':') {
		return error(invalid)
	}
	return trimmed
}

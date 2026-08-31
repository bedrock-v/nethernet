// Package endpoint implements NetherNet's HTTP signalling: direct connect to
// a dedicated server by address, not LAN broadcast or Xbox Live.
//
// GET /v1/join is a discovery ping, tried against https://host:port,
// https://host, http://host:port, http://host in order. POST
// /v1/join/{networkID} exchanges one SDP offer for one answer. No trickle
// ICE: both ends gather and embed every candidate before signalling.
module endpoint

import net.http
import rand
import sync
import time
import nethernet
import bedrock_v.webrtc.logging

const max_sdp_body_size = 1 << 20

// HandlerConfig configures an EndpointHandler.
@[params]
pub struct HandlerConfig {
pub:
	// address is what the underlying HTTP server binds, e.g. :19132. Bedrock
	// clients probe the game's own address.
	address string
	// cert and cert_key, given together, make the server accept HTTPS instead
	// of HTTP. A client tries https first, so a publicly reachable server
	// wants both set.
	cert     string
	cert_key string
	// network_id identifies this handler for logging only, never sent to
	// clients. Empty picks a random one; the resolved value lives on
	// EndpointHandler.network_id.
	network_id string
	// negotiation_timeout bounds how long one POST /v1/join/{id} request waits
	// for the registered listener to produce an answer.
	negotiation_timeout time.Duration = 15 * time.second
	// credentials overrides the ICE servers handed out for gathering local
	// candidates. Unset returns none, the same as a LAN signalling channel.
	credentials ?nethernet.Credentials
	logger      logging.Logger = logging.nop()
}

// EndpointHandler is a nethernet.Signaling implementation backed by an
// HTTP(S) server: GET /v1/join and POST /v1/join/{networkID}. Pass it to
// nethernet.listen.
//
// notify accepts multiple simultaneous subscribers: nethernet.Listener
// registers one per in-flight negotiation, not just one for itself.
pub struct EndpointHandler {
mut:
	config HandlerConfig
	log    logging.Logger
	server &http.Server = unsafe { nil }

	// pending tracks negotiations waiting for an answer, keyed by
	// connection_key(network_id, connection_id). Each entry is a fresh,
	// capacity-1 channel created for that one request.
	pending    map[string]chan nethernet.Signal
	pending_mu &sync.Mutex = sync.new_mutex()

	// notifiers are the subscriptions an offer is broadcast to; only the
	// Listener's own subscription accepts a signal_type_offer.
	notifiers      map[int]nethernet.Notifier
	notifier_count int
	notifier_mu    &sync.Mutex = sync.new_mutex()

	// status is what a discovery ping is answered with. It stays empty until a
	// server describes itself, and a ping is answered with no body until then.
	status    ?Status
	status_mu &sync.Mutex = sync.new_mutex()

	closed   bool
	close_mu &sync.Mutex = sync.new_mutex()
pub:
	// network_id is HandlerConfig.network_id after listen() resolves an empty
	// value to a random one.
	network_id string
}

// listen starts an EndpointHandler's HTTP server and returns once it is
// actually accepting connections.
pub fn listen(config HandlerConfig) !&EndpointHandler {
	mut network_id := config.network_id
	if network_id == '' {
		network_id = rand.u64().str()
	}

	mut h := &EndpointHandler{
		config:     config
		log:        config.logger.with_scope('nethernet/endpoint')
		network_id: network_id
	}

	mut server := &http.Server{
		addr:     config.address
		handler:  h
		cert:     config.cert
		cert_key: config.cert_key
		// The caller has a logger of its own; the server's own banner would
		// reach stdout without going through it.
		show_startup_message: false
	}
	h.server = server

	spawn server.listen_and_serve()
	server.wait_till_running() or {
		return error('nethernet/endpoint: server did not start: ${err.msg()}')
	}
	return h
}

pub fn (h &EndpointHandler) network_id() string {
	return h.network_id
}

// disable_trickle_ice always returns true: an HTTP request/response round
// trip can't carry a candidate after the answer has already been sent back.
pub fn (h &EndpointHandler) disable_trickle_ice() bool {
	return true
}

pub fn (mut h EndpointHandler) credentials() !nethernet.Credentials {
	if h.is_closed() {
		return error('nethernet/endpoint: handler closed')
	}
	return h.config.credentials or { nethernet.Credentials{} }
}

// pong_data sets what a discovery ping is answered with, reading the RakNet
// pong response a Bedrock server layer already produces for its MOTD.
pub fn (mut h EndpointHandler) pong_data(data []u8) {
	status := Status.from_pong(data) or {
		h.log.error('reading pong data: ${err.msg()}')
		return
	}
	h.set_status(status)
}

// set_status sets what a discovery ping is answered with, for a caller that
// has no RakNet pong to hand over.
pub fn (mut h EndpointHandler) set_status(status Status) {
	h.status_mu.lock()
	h.status = status
	h.status_mu.unlock()
}

pub fn (mut h EndpointHandler) is_closed() bool {
	h.close_mu.lock()
	defer {
		h.close_mu.unlock()
	}
	return h.closed
}

// close stops the underlying HTTP server and drops the registered listener.
pub fn (mut h EndpointHandler) close() {
	h.close_mu.lock()
	if h.closed {
		h.close_mu.unlock()
		return
	}
	h.closed = true
	h.close_mu.unlock()

	if h.server != unsafe { nil } {
		h.server.stop()
		h.server.close()
	}

	h.notifier_mu.lock()
	h.notifiers.clear()
	h.notifier_mu.unlock()
}

// notify subscribes n to incoming signals and returns the subscription ID.
pub fn (mut h EndpointHandler) notify(n nethernet.Notifier) int {
	h.notifier_mu.lock()
	defer {
		h.notifier_mu.unlock()
	}
	id := h.notifier_count
	h.notifiers[id] = n
	h.notifier_count++
	return id
}

pub fn (mut h EndpointHandler) stop_notify(id int) {
	h.notifier_mu.lock()
	h.notifiers.delete(id)
	h.notifier_mu.unlock()
}

// signal delivers sig, an answer or error, to the pending HTTP request
// waiting on connection_key(sig.network_id, sig.connection_id).
pub fn (mut h EndpointHandler) signal(sig nethernet.Signal) ! {
	if sig.typ == nethernet.signal_type_candidate {
		return error('nethernet/endpoint: disable trickle ICE to use EndpointHandler')
	}
	key := connection_key(sig.network_id, sig.connection_id)
	h.pending_mu.lock()
	ch := h.pending[key] or {
		h.pending_mu.unlock()
		return error('nethernet/endpoint: unexpected connection ID: ${key}')
	}
	h.pending_mu.unlock()

	select {
		ch <- sig {
			return
		}
		else {
			return error('nethernet/endpoint: channel buffer is full')
		}
	}
}

// handle implements http.Handler, routing GET /v1/join and
// POST /v1/join/{networkID}. Every other request gets a plain 404.
pub fn (mut h EndpointHandler) handle(req http.Request) http.Response {
	// Whether a client ever reaches the endpoint is otherwise invisible: it
	// probes HTTPS before HTTP and falls back to RakNet on its own, so a join
	// that never arrives looks exactly like one that was never attempted.
	h.log.debug('${req.method} ${req.url}')
	if req.method == .get && req.url == '/v1/join' {
		return h.handle_ping()
	}
	if req.method == .post && req.url.starts_with('/v1/join/') {
		return h.handle_offer(req)
	}
	h.log.debug('nothing is served at ${req.method} ${req.url}')
	return text_response(.not_found, 'not found')
}

// handle_ping answers a GET /v1/join with the server's status, or with an
// empty body while none has been set.
fn (mut h EndpointHandler) handle_ping() http.Response {
	h.status_mu.lock()
	status := h.status
	h.status_mu.unlock()

	current := status or {
		h.log.debug('answering a ping with no status: none has been set')
		mut resp := http.Response{}
		resp.set_status(.ok)
		return resp
	}
	body := current.encode()
	h.log.debug('answering a ping with ${body}')
	mut resp := http.Response{
		body: body
	}
	resp.header.set(.content_type, 'application/json')
	resp.set_status(.ok)
	return resp
}

// handle_offer answers a POST /v1/join/{networkID} request: it reads the SDP
// offer from the body, hands it to the registered listener and waits for the
// answer to write back.
fn (mut h EndpointHandler) handle_offer(req http.Request) http.Response {
	network_id := req.url.all_after('/v1/join/').trim_right('/')
	if network_id == '' {
		return text_response(.bad_request, 'Expected /v1/join/{networkID}')
	}
	if !all_digits(network_id) {
		return text_response(.bad_request, 'Network ID must be uint64')
	}
	if req.data.len == 0 {
		return text_response(.bad_request, 'Missing SDP offer in request body')
	}
	if req.data.len > max_sdp_body_size {
		return text_response(.request_entity_too_large, 'SDP offer is too large')
	}

	h.log.debug('an offer of ${req.data.len} bytes arrived for network ${network_id}')
	sig := h.negotiate(network_id, req.data) or {
		msg := err.msg()
		if msg.contains('not admitted') {
			return text_response(.service_unavailable, 'Service unavailable')
		}
		if msg.contains('timed out') {
			return text_response(.bad_gateway, 'Timed out waiting for answer')
		}
		h.log.error('negotiating offer from network ${network_id}: ${msg}')
		return text_response(.internal_server_error,
			'An error has occurred while handling this request')
	}

	match sig.typ {
		nethernet.signal_type_answer {
			mut resp := http.Response{
				body: sig.data
			}
			resp.header.set(.content_type, 'application/sdp')
			resp.set_status(.ok)
			return resp
		}
		nethernet.signal_type_error {
			return text_response(.bad_request, 'Negotiation failed with error code: ${sig.data}')
		}
		else {
			h.log.error('unexpected negotiation result: ${sig.typ}')
			return text_response(.internal_server_error,
				'An error has occurred while handling this request')
		}
	}
}

// notifier_snapshot copies the current subscriptions so they can be broadcast
// to without holding notifier_mu across a call into arbitrary Notifier code.
fn (mut h EndpointHandler) notifier_snapshot() []nethernet.Notifier {
	h.notifier_mu.lock()
	defer {
		h.notifier_mu.unlock()
	}
	mut out := []nethernet.Notifier{cap: h.notifiers.len}
	for _, n in h.notifiers {
		out << n
	}
	return out
}

// negotiate broadcasts the offer to every subscriber and waits for the
// answer or the configured timeout. Admitted once any subscriber accepts it
// - only the Listener itself ever does.
fn (mut h EndpointHandler) negotiate(network_id string, offer string) !nethernet.Signal {
	mut notifiers := h.notifier_snapshot()
	if notifiers.len == 0 {
		return error('nethernet/endpoint: no listener registered')
	}

	connection_id := rand.u64()
	key := connection_key(network_id, connection_id)
	ch := chan nethernet.Signal{cap: 1}

	h.pending_mu.lock()
	h.pending[key] = ch
	h.pending_mu.unlock()
	defer {
		h.pending_mu.lock()
		h.pending.delete(key)
		h.pending_mu.unlock()
	}

	sig := nethernet.Signal{
		typ:           nethernet.signal_type_offer
		connection_id: connection_id
		data:          offer
		network_id:    network_id
	}

	mut admitted := false
	for mut n in notifiers {
		if n.notify_signal(sig) {
			admitted = true
		}
	}
	if !admitted {
		return error('nethernet/endpoint: offer not admitted')
	}

	mut result := nethernet.Signal{}
	select {
		result = <-ch {
			return result
		}
		h.config.negotiation_timeout {
			mut timeout_notifiers := h.notifier_snapshot()
			for mut n in timeout_notifiers {
				n.notify_signal(nethernet.Signal{
					typ:           nethernet.signal_type_error
					connection_id: connection_id
					data:          nethernet.error_code_negotiation_timeout_waiting_for_response.str()
					network_id:    network_id
				})
			}
			return error('nethernet/endpoint: negotiation timed out waiting for an answer')
		}
	}
	return error('nethernet/endpoint: negotiation ended unexpectedly')
}

// connection_key identifies one in progress negotiation.
fn connection_key(network_id string, connection_id u64) string {
	return '${network_id}/${connection_id}'
}

fn all_digits(s string) bool {
	if s.len == 0 {
		return false
	}
	for b in s {
		if b < `0` || b > `9` {
			return false
		}
	}
	return true
}

fn text_response(status http.Status, text string) http.Response {
	mut resp := http.Response{
		body: text
	}
	resp.header.set(.content_type, 'text/plain')
	resp.set_status(status)
	return resp
}

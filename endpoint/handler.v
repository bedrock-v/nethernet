// Package endpoint is the address join half of NetherNet.
//
// A client joining by address does not broadcast: it asks the address itself
// over HTTP. It pings `GET /v1/join` at https://host:port, https://host,
// http://host:port and http://host in turn and stops at the first that answers,
// then posts its SDP offer to `POST /v1/join/{networkID}` and reads the answer
// out of the response body. A server that answers none of those pings is looked
// for over RakNet instead.
//
// The whole exchange is one request and one response, so there is nowhere to
// put a candidate that arrives later: every local candidate has to be gathered
// before the answer is written.
module endpoint

import net
import net.http
import rand
import sync
import time
import nethernet
import webrtc.logging

// max_offer_size caps the SDP a client may post. An offer with every candidate
// embedded is a few kilobytes; this leaves room without letting a request hold
// a worker on an unbounded body.
const max_offer_size = 1 << 20

@[params]
pub struct HandlerConfig {
pub:
	// network_id identifies this endpoint locally. It is never sent to a client
	// - the client names the network in the path it posts to - so a random one
	// is as good as any.
	network_id u64
	// negotiation_timeout bounds how long a posted offer waits for the answer
	// the listener produces. The client is holding a request open for all of it.
	negotiation_timeout time.Duration  = 15 * time.second
	logger              logging.Logger = logging.nop()
}

// Handler is the signalling channel behind an address join.
//
// It is a NetherNet Signaling implementation whose transport is HTTP rather
// than a socket the peers keep open: an offer arrives as a request body and the
// answer leaves as the response to that same request. Pass it to
// nethernet.listen to host.
@[heap]
pub struct Handler {
mut:
	config HandlerConfig
	log    logging.Logger
	id     u64

	// pending holds the channel each in flight negotiation is waiting on, keyed
	// by the connection it belongs to. The request handler parks on the channel
	// until the listener signals back through signal.
	pending    map[string]chan nethernet.Signal
	pending_mu &sync.RwMutex = sync.new_rwmutex()

	// notifier is the single listener offers are handed to. One request can
	// only ever produce one answer, so a second subscriber would have nothing
	// to answer with.
	notifier      ?nethernet.Notifier
	notify_count  int
	notifier_id   int
	notifiers_mu  &sync.RwMutex = sync.new_rwmutex()

	// status is what a ping is answered with. It is empty until a server sets
	// one, and a ping is answered with no body until then.
	status    ?Status
	status_mu &sync.RwMutex = sync.new_rwmutex()

	server   &http.Server = unsafe { nil }
	closed   bool
	close_mu &sync.Mutex = sync.new_mutex()
}

// new_handler builds a Handler without binding it, for a caller that runs its
// own HTTP server and routes to handle.
pub fn new_handler(config HandlerConfig) &Handler {
	mut id := config.network_id
	if id == 0 {
		id = rand.u64()
	}
	return &Handler{
		config: config
		log:    config.logger.with_scope('nethernet/endpoint')
		id:     id
	}
}

// listen starts a Handler on addr.
//
// The client tries HTTPS before HTTP on the address it was given, so a plain
// server answers on the second attempt rather than the first. That costs one
// round trip and nothing else: the negotiation that follows is encrypted by
// DTLS regardless of how the offer reached the server.
pub fn listen(addr string, config HandlerConfig) !&Handler {
	// The socket is opened here rather than left to the server thread, so a
	// port that is already taken is reported to the caller instead of being
	// logged somewhere it cannot act on, and so the bound address is known
	// before the first request arrives.
	mut socket := net.listen_tcp(.ip, addr) or {
		return error('endpoint: binding ${addr}: ${err.msg()}')
	}
	bound := socket.addr() or {
		socket.close() or {}
		return error('endpoint: reading the bound address: ${err.msg()}')
	}
	mut h := new_handler(config)
	mut server := &http.Server{
		addr:                 bound.str()
		listener:             socket
		handler:              h
		show_startup_message: false
	}
	h.server = server
	spawn server.listen_and_serve()
	return h
}

// addr is the address the bound HTTP server ended up on, which is what a
// caller that asked for port zero needs to know.
pub fn (h &Handler) addr() string {
	if isnil(h.server) {
		return ''
	}
	return h.server.addr
}

// network_id is the local network ID, in the string form NetherNet uses.
pub fn (h &Handler) network_id() string {
	return h.id.str()
}

// disable_trickle_ice reports true: an answer is written once, as the response
// to the request that carried the offer, so there is no second message a
// candidate could travel in.
pub fn (h &Handler) disable_trickle_ice() bool {
	return true
}

// credentials returns no ICE servers. A caller that needs STUN or TURN to be
// reachable has to supply them itself.
pub fn (mut h Handler) credentials() !nethernet.Credentials {
	if h.is_closed() {
		return error('endpoint: handler closed')
	}
	return nethernet.Credentials{}
}

// signal hands an answer or an error back to the request that is waiting for
// it. A candidate has nowhere to go and is refused.
pub fn (mut h Handler) signal(sig nethernet.Signal) ! {
	if h.is_closed() {
		return error('endpoint: handler closed')
	}
	if sig.typ == nethernet.signal_type_candidate {
		return error('endpoint: a candidate cannot be sent after the answer')
	}
	key := pending_key(sig.network_id, sig.connection_id)
	h.pending_mu.@rlock()
	channel := h.pending[key] or {
		h.pending_mu.runlock()
		return error('endpoint: nothing is waiting on connection ${key}')
	}
	h.pending_mu.runlock()

	select {
		channel <- sig {}
		else {
			return error('endpoint: the answer for connection ${key} arrived twice')
		}
	}
}

// notify subscribes n to incoming offers and returns the subscription ID.
pub fn (mut h Handler) notify(n nethernet.Notifier) int {
	h.notifiers_mu.@lock()
	defer {
		h.notifiers_mu.unlock()
	}
	h.notify_count++
	h.notifier_id = h.notify_count
	h.notifier = n
	return h.notifier_id
}

// stop_notify cancels a subscription, unless it has already been replaced.
pub fn (mut h Handler) stop_notify(id int) {
	h.notifiers_mu.@lock()
	if h.notifier_id == id {
		h.notifier = none
	}
	h.notifiers_mu.unlock()
}

// pong_data sets what a ping is answered with, from a RakNet pong response.
pub fn (mut h Handler) pong_data(data []u8) {
	status := Status.from_pong(data) or {
		h.log.error('reading pong data: ${err.msg()}')
		return
	}
	h.set_status(status)
}

// set_status sets what a ping is answered with.
pub fn (mut h Handler) set_status(status Status) {
	h.status_mu.@lock()
	h.status = status
	h.status_mu.unlock()
}

// is_closed reports whether the handler has been closed.
pub fn (mut h Handler) is_closed() bool {
	h.close_mu.lock()
	defer {
		h.close_mu.unlock()
	}
	return h.closed
}

// close stops answering and drops the subscription.
pub fn (mut h Handler) close() {
	h.close_mu.lock()
	if h.closed {
		h.close_mu.unlock()
		return
	}
	h.closed = true
	h.close_mu.unlock()

	if !isnil(h.server) {
		h.server.close()
	}

	h.notifiers_mu.@lock()
	h.notifier = none
	h.notifiers_mu.unlock()
}

// handle routes one request. It is the http.Handler side of the endpoint.
pub fn (mut h Handler) handle(req http.Request) http.Response {
	if h.is_closed() {
		return text_response(.service_unavailable, 'Service unavailable')
	}
	path := request_path(req.url)
	if req.method == .get && path == '/v1/join' {
		return h.handle_ping()
	}
	if req.method == .post && path.starts_with('/v1/join/') {
		return h.handle_offer(path['/v1/join/'.len..], req.data)
	}
	return text_response(.not_found, 'Not found')
}

// handle_ping answers with the status, or with nothing when a server has not
// described itself yet.
fn (mut h Handler) handle_ping() http.Response {
	h.status_mu.@rlock()
	status := h.status
	h.status_mu.runlock()

	current := status or { return text_response(.ok, '') }
	mut header := http.new_header()
	header.add(.content_type, 'application/json')
	return http.new_response(
		status: .ok
		body:   current.encode()
		header: header
	)
}

// handle_offer runs one negotiation: the offer goes to the listener, and
// whatever it signals back becomes the response.
fn (mut h Handler) handle_offer(network_id string, offer string) http.Response {
	if network_id == '' || network_id.u64() == 0 {
		return text_response(.bad_request, 'Network ID must be a number')
	}
	if offer == '' {
		return text_response(.bad_request, 'Missing SDP offer in request body')
	}
	if offer.len > max_offer_size {
		return text_response(.request_entity_too_large, 'SDP offer is too large')
	}

	sig := h.negotiate(network_id, offer) or {
		h.log.error('negotiating a connection with network ${network_id}: ${err.msg()}')
		return text_response(.service_unavailable, 'Service unavailable')
	}
	if sig.typ == nethernet.signal_type_error {
		return text_response(.internal_server_error, sig.data)
	}
	if sig.typ != nethernet.signal_type_answer {
		h.log.error('negotiating a connection with network ${network_id}: answered with ${sig.typ}')
		return text_response(.internal_server_error, 'An error has occurred while handling this request')
	}
	mut header := http.new_header()
	header.add(.content_type, 'application/sdp')
	return http.new_response(
		status: .ok
		body:   sig.data
		header: header
	)
}

// negotiate hands the offer to the listener and waits for the answer it
// produces, giving up once the negotiation timeout passes.
fn (mut h Handler) negotiate(network_id string, offer string) !nethernet.Signal {
	h.notifiers_mu.@rlock()
	mut notifier := h.notifier
	h.notifiers_mu.runlock()
	mut subscriber := notifier or { return error('no listener is registered') }

	// The connection ID is the server's to pick here: a client joining by
	// address never names one, because the request itself is the connection.
	connection_id := rand.u64()
	key := pending_key(network_id, connection_id)
	channel := chan nethernet.Signal{cap: 1}

	h.pending_mu.@lock()
	h.pending[key] = channel
	h.pending_mu.unlock()
	defer {
		h.pending_mu.@lock()
		h.pending.delete(key)
		h.pending_mu.unlock()
	}

	if !subscriber.notify_signal(nethernet.Signal{
		typ:           nethernet.signal_type_offer
		connection_id: connection_id
		data:          offer
		network_id:    network_id
	})
	{
		return error('the listener refused the offer')
	}

	select {
		sig := <-channel {
			return sig
		}
		h.config.negotiation_timeout {
			subscriber.notify_signal(nethernet.Signal{
				typ:           nethernet.signal_type_error
				connection_id: connection_id
				data:          nethernet.error_code_negotiation_timeout.str()
				network_id:    network_id
			})
			return error('timed out waiting for an answer')
		}
	}
	return error('the answer channel closed')
}

fn pending_key(network_id string, connection_id u64) string {
	return '${network_id}/${connection_id}'
}

// request_path strips the query off a request target, which is all the routing
// here cares about.
fn request_path(url string) string {
	if index := url.index('?') {
		return url[..index]
	}
	return url
}

fn text_response(status http.Status, body string) http.Response {
	mut header := http.new_header()
	header.add(.content_type, 'text/plain')
	return http.new_response(
		status: status
		body:   body
		header: header
	)
}

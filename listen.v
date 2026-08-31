module nethernet

import crypto.ecdsa
import sync
import time
import bedrock_v.webrtc
import bedrock_v.webrtc.ice
import bedrock_v.webrtc.logging

// ListenConfig configures a Listener.
//
// The zero value listens with a freshly generated server identity and refuses
// anonymous clients, which is what a server exposed to the internet wants. A
// LAN server that expects offline clients has to set allow_anonymous.
@[params]
pub struct ListenConfig {
pub:
	// identity is presented to every client in the answer. Without one, the
	// listener generates a key at startup and self-signs a token per
	// connection - which means a client using trust on first use sees a
	// different server after every restart.
	identity ?Identity
	// allow_anonymous accepts offers with no identity assertion.
	//
	// It gives up the binding between the client's key and this connection, so a
	// Login packet captured from another connection can be replayed onto this
	// one. Enable it only where the network is trusted.
	allow_anonymous bool
	// interfaces filters which local addresses become ICE candidates. Every
	// address gathered is disclosed to the peer, so it is a privacy control as
	// much as a connectivity one.
	interfaces ice.InterfaceOptions
	// ice_gather_policy limits which local candidates are gathered.
	ice_gather_policy ice.GatherPolicy = .all
	// disable_trickle_ice gathers every candidate before sending the answer and
	// embeds them in it, for a client that cannot accept them separately.
	disable_trickle_ice bool
	// negotiation_timeout bounds one connection's negotiation, from the offer
	// arriving to the transports coming up.
	negotiation_timeout time.Duration  = 30 * time.second
	logger              logging.Logger = logging.nop()
}

// Listener accepts NetherNet connections offered to a local network.
//
// It subscribes to the signalling channel for offers. Everything else - the
// candidates and the errors belonging to a connection already being
// negotiated - is delivered to that connection directly, so the listener does
// not have to route it.
pub struct Listener {
mut:
	signaling    Signaling
	config       ListenConfig
	log          logging.Logger
	subscription int

	// identity holds the key the server answers under. The key is kept for the
	// listener's lifetime, so a client that remembers it sees the same server,
	// while the token itself is reissued for every connection.
	identity Identity

	offers   chan Signal
	incoming chan &Conn

	closed   bool
	close_mu &sync.Mutex = sync.new_mutex()
pub:
	// network_id is the local network this listener answers for.
	network_id string
}

// listen starts accepting connections offered to the signalling channel's local
// network.
pub fn listen(mut signaling Signaling, config ListenConfig) !&Listener {
	log := config.logger.with_scope('nethernet/listen')

	identity := config.identity or {
		// A key generated here is not persisted, so a client using trust on
		// first use treats every restart as a different server. A caller that
		// cares should pass an identity built from a stored key.
		log.warn('no server identity was configured; generating a temporary one')
		private_key := ecdsa.PrivateKey.new(nid: .secp384r1)!
		generate_server_identity(private_key, 'self')!
	}

	mut l := &Listener{
		signaling:  signaling
		config:     config
		log:        log
		identity:   identity
		network_id: signaling.network_id()
		offers:     chan Signal{cap: signal_queue_size}
		incoming:   chan &Conn{cap: pending_connections}
	}
	l.subscription = signaling.notify(l)
	spawn l.run()
	return l
}

// pending_connections bounds how many negotiated connections may wait to be
// accepted before the listener stops taking new offers.
const pending_connections = 16

// accept returns the next established connection, waiting up to timeout.
pub fn (mut l Listener) accept(timeout time.Duration) !&Conn {
	if l.is_closed() {
		return error('nethernet: listener closed')
	}
	mut conn := &Conn(unsafe { nil })
	select {
		conn = <-l.incoming {
			return conn
		}
		timeout {
			return error('nethernet: no connection was offered within ${timeout.milliseconds()}ms')
		}
	}
	return error('nethernet: listener closed')
}

// addr is the address this listener answers for.
pub fn (l &Listener) addr() Addr {
	return Addr{
		network_id: l.network_id
	}
}

// id is the network ID as the number the discovery layer carries it as.
pub fn (l &Listener) id() u64 {
	return l.network_id.u64()
}

// pong_data sets the server data advertised to clients looking for a game, in
// the format of a RakNet pong response.
pub fn (mut l Listener) pong_data(data []u8) {
	l.signaling.pong_data(data)
}

// notify_signal queues an offer. Every other signal belongs to a connection
// already being negotiated, which is subscribed for it in its own right.
fn (mut l Listener) notify_signal(sig Signal) bool {
	if sig.typ != signal_type_offer {
		return false
	}
	select {
		l.offers <- sig {
			return true
		}
		else {
			l.log.warn('dropping an offer from network ${sig.network_id}: the queue is full')
			return false
		}
	}
	return false
}

// close stops the listener. Connections it already handed out stay open.
pub fn (mut l Listener) close() {
	l.close_mu.lock()
	if l.closed {
		l.close_mu.unlock()
		return
	}
	l.closed = true
	l.close_mu.unlock()

	l.signaling.stop_notify(l.subscription)
	l.offers.close()
	l.incoming.close()
}

// is_closed reports whether the listener has stopped accepting. It follows the
// signalling channel: a listener whose signals have stopped can no longer be
// offered anything.
pub fn (mut l Listener) is_closed() bool {
	l.close_mu.lock()
	defer {
		l.close_mu.unlock()
	}
	return l.closed || l.signaling.is_closed()
}

// run takes offers off the queue and negotiates each one.
fn (mut l Listener) run() {
	for !l.is_closed() {
		mut sig := Signal{}
		select {
			sig = <-l.offers {}
			signal_poll_interval {
				continue
			}
		}
		if sig.typ != signal_type_offer {
			continue
		}

		// The collector is registered here rather than in the negotiation
		// thread: a client starts trickling candidates as soon as it has sent
		// the offer, and one that arrives before anything is subscribed for it
		// is lost.
		mut collector := &SignalCollector{
			connection_id: sig.connection_id
			network_id:    sig.network_id
			signals:       chan Signal{cap: signal_queue_size}
			log:           l.log
		}
		subscription := l.signaling.notify(collector)

		mut negotiation := &Negotiation{
			listener:     unsafe { l }
			offer:        sig
			collector:    collector
			subscription: subscription
		}
		spawn negotiation.run()
	}
}

// Negotiation turns one offer into an established connection.
//
// It runs in its own thread: bringing up ICE, DTLS and SCTP takes seconds, and
// the listener has to stay free to take the next offer.
struct Negotiation {
mut:
	listener     &Listener        = unsafe { nil }
	collector    &SignalCollector = unsafe { nil }
	offer        Signal
	subscription int
}

fn (mut n Negotiation) run() {
	mut l := n.listener
	mut conn := n.negotiate() or {
		l.log.error('negotiating a connection from network ${n.offer.network_id}: ${err.msg()}')
		l.signaling.stop_notify(n.subscription)
		mut signaling := l.signaling
		signal_error(mut signaling, n.offer.network_id, n.offer.connection_id,
			listen_error_code(err))
		return
	}

	select {
		l.incoming <- conn {}
		n.listener.config.negotiation_timeout {
			// Nobody is accepting, and holding the connection open would keep a
			// peer believing it is in a game it will never join.
			conn.close_with('the listener did not accept the connection in time')
		}
	}
}

// negotiate answers the offer and waits for the transports to come up.
fn (mut n Negotiation) negotiate() !&Conn {
	mut l := n.listener
	deadline := time.now().add(l.config.negotiation_timeout)

	credentials := l.signaling.credentials()!
	mut pc := webrtc.PeerConnection.new(
		ice_servers:       credentials.to_webrtc()
		ice_gather_policy: l.config.ice_gather_policy
		interfaces:        l.config.interfaces
		max_message_size:  max_message_size + 1
		logger:            l.config.logger
	)!

	mut conn := &Conn{
		pc:               pc
		id:               n.offer.connection_id
		network_id:       n.offer.network_id
		local_network_id: l.network_id
	}
	n.verify_client(mut conn, n.offer.data)!

	pc.set_remote_description(webrtc.SessionDescription{
		typ: .offer
		sdp: n.offer.data
	})!
	// A client that cannot trickle puts its candidates in the offer.
	for candidate in description_candidates(n.offer.data) {
		pc.add_ice_candidate(candidate) or { continue }
	}

	answer := pc.create_answer()!
	// The key is the listener's, but the token is minted here: one signed at
	// startup would have expired by the time a player joins a server that has
	// been up for longer than a token lives.
	identity := l.identity.reissue()!
	sdp_text := inject_identity(answer.sdp, identity.sign(answer.sdp)!)

	ufrag := media_attribute(sdp_text, 'ice-ufrag') or {
		return error('nethernet: the local answer carries no ICE credentials')
	}

	disable_trickle := l.config.disable_trickle_ice || l.signaling.disable_trickle_ice()

	// disable_trickle: the peer hasn't received this description yet, so
	// bring-up must not start until it has - see
	// webrtc.PeerConnection.set_local_description_deferred's own doc comment.
	mut answered := sdp_text
	if disable_trickle {
		pc.set_local_description_deferred(webrtc.SessionDescription{
			typ: .answer
			sdp: sdp_text
		})!
		answered = embed_candidates(sdp_text, conn.gather_candidates(ufrag,
			l.config.negotiation_timeout)!)
	} else {
		pc.set_local_description(webrtc.SessionDescription{
			typ: .answer
			sdp: sdp_text
		})!
	}

	mut signaling := l.signaling
	signaling.signal(Signal{
		typ:           signal_type_answer
		connection_id: conn.id
		data:          answered
		network_id:    conn.network_id
	})!

	if disable_trickle {
		pc.begin_connecting()
	}

	if !disable_trickle {
		mut trickler := &CandidateTrickler{
			conn:      conn
			signaling: signaling
			ufrag:     ufrag
			log:       l.log
		}
		spawn trickler.run()
	}

	mut pump := &SignalPump{
		conn:         conn
		collector:    n.collector
		signaling:    signaling
		subscription: n.subscription
		log:          l.log
	}
	spawn pump.run()

	remaining := deadline - time.now()
	if remaining <= 0 {
		return error('nethernet: negotiation timed out before the transports were started')
	}
	pc.wait_connected(remaining)!
	n.adopt_channels(mut conn, deadline)!
	return conn
}

// adopt_channels takes the two data channels the client opened.
//
// The client opens both, so a listener waits for them rather than creating
// them. A channel whose parameters do not match either reliability is not one
// of ours, and a peer that opens one is not speaking NetherNet.
fn (mut n Negotiation) adopt_channels(mut conn Conn, deadline time.Time) ! {
	for conn.reliable == unsafe { nil } || conn.unreliable == unsafe { nil } {
		remaining := deadline - time.now()
		if remaining <= 0 {
			return error('nethernet: the peer did not open both data channels in time')
		}
		mut channel := conn.pc.accept_data_channel(remaining)!

		if MessageReliability.reliable.matches(mut channel) {
			if conn.reliable != unsafe { nil } {
				return error('nethernet: the peer opened ${MessageReliability.reliable.label()} twice')
			}
			conn.reliable = channel
		} else if MessageReliability.unreliable.matches(mut channel) {
			if conn.unreliable != unsafe { nil } {
				return error('nethernet: the peer opened ${MessageReliability.unreliable.label()} twice')
			}
			conn.unreliable = channel
		} else {
			return error('nethernet: the peer opened an unexpected data channel "${channel.label}"')
		}
	}
}

// verify_client checks the client's identity assertion, if it made one.
//
// The token itself is issued by Minecraft's authorization service and signed
// with RS256, which this package cannot verify; only the binding between the
// token's key and this connection's fingerprints is checked here. A server must
// also verify the Login packet's token at the protocol layer and confirm it
// names the same key - otherwise a client may present any token it likes over a
// connection it legitimately holds the key for.
fn (mut n Negotiation) verify_client(mut conn Conn, sdp_text string) ! {
	identity := extract_identity(sdp_text) or {
		if n.listener.config.allow_anonymous {
			return
		}
		return error('nethernet: the offer carries no identity assertion')
	}
	public_key := claim_public_key(identity.token, false)!
	identity.verify(sdp_text, public_key)!

	conn.public_key = public_key
	conn.remote_domain = identity.domain
}

// listen_error_code maps a failed negotiation onto the code the client is told
// about.
fn listen_error_code(err IError) int {
	message := err.msg()
	if message.contains('identity') || message.contains('token') {
		return error_code_identity_verification_failed
	}
	if message.contains('data channel') {
		return error_code_data_channel_closed
	}
	if message.contains('timed out') || message.contains('in time') {
		return error_code_negotiation_timeout_waiting_for_accept
	}
	return error_code_failed_to_create_answer
}

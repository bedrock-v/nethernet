module nethernet

import crypto.ecdsa
import rand
import time
import webrtc
import webrtc.ice
import webrtc.logging

// DialConfig configures one dial. The zero value connects anonymously to a peer
// that allows it, which is what a LAN game does.
@[params]
pub struct DialConfig {
pub:
	// connection_id references this connection in every signal exchanged for it.
	// Zero picks a random one, which is what a caller should normally do.
	connection_id u64
	// identity is presented to the server in the offer. Without one, the offer
	// carries no `a=identity` attribute and only a server that allows anonymous
	// clients will answer.
	identity ?Identity
	// allow_identityless_server accepts an answer with no identity assertion.
	// The server is then unauthenticated - useful against custom or legacy
	// implementations, and a downgrade everywhere else.
	allow_identityless_server bool
	// credentials overrides the ICE servers the signalling channel hands out,
	// for a caller that would rather gather through its own STUN or TURN.
	credentials ?Credentials
	// interfaces filters which local addresses become ICE candidates. Every
	// address gathered is disclosed to the peer, so it is a privacy control as
	// much as a connectivity one.
	interfaces ice.InterfaceOptions
	// ice_gather_policy limits which local candidates are gathered.
	ice_gather_policy ice.GatherPolicy = .all
	// disable_trickle_ice gathers every candidate before sending the offer and
	// embeds them in it. It is slower, and it is what a dedicated server with
	// the `nethernet-disable-trickle-ice` setting requires.
	disable_trickle_ice bool
	// timeout bounds the whole negotiation, from the offer to the transports
	// coming up.
	timeout time.Duration  = 30 * time.second
	logger  logging.Logger = logging.nop()
}

// dial establishes a connection to the network named by network_id.
//
// The signalling channel carries the offer out and the answer back. Once both
// descriptions are in place, ICE, DTLS and SCTP come up and the two data
// channels open; the returned connection is ready to read and write.
pub fn dial(network_id string, mut signaling Signaling, config DialConfig) !&Conn {
	mut connection_id := config.connection_id
	if connection_id == 0 {
		connection_id = rand.u64()
	}
	log := config.logger.with_scope('nethernet/dial')
	deadline := time.now().add(config.timeout)

	credentials := config.credentials or { signaling.credentials()! }
	mut pc := webrtc.PeerConnection.new(
		ice_servers:       credentials.to_webrtc()
		ice_gather_policy: config.ice_gather_policy
		interfaces:        config.interfaces
		max_message_size:  max_message_size + 1
		logger:            config.logger
	)!

	mut conn := &Conn{
		pc:               pc
		id:               connection_id
		network_id:       network_id
		local_network_id: signaling.network_id()
	}
	// The client opens both channels. A server that opens one is not speaking
	// NetherNet, and accepting it would leave the channel's reliability unknown.
	conn.reliable = pc.create_data_channel(MessageReliability.reliable.label(),
		MessageReliability.reliable.options())!
	conn.unreliable = pc.create_data_channel(MessageReliability.unreliable.label(),
		MessageReliability.unreliable.options())!

	mut collector := &SignalCollector{
		connection_id: connection_id
		network_id:    network_id
		signals:       chan Signal{cap: signal_queue_size}
		log:           log
	}
	subscription := signaling.notify(collector)

	// The pump feeds candidates to ICE for as long as the connection lives. It
	// starts before the offer, because a server may answer and begin trickling
	// before this thread gets back to reading.
	mut pump := &SignalPump{
		conn:         conn
		collector:    collector
		signaling:    signaling
		subscription: subscription
		log:          log
	}

	negotiate_dial(mut conn, mut signaling, mut pump, config, deadline, log) or {
		pump.stop()
		signaling.stop_notify(subscription)
		signal_error(mut signaling, network_id, connection_id, dial_error_code(err))
		conn.close_with(err.msg())
		return err
	}
	return conn
}

// negotiate_dial runs the offer/answer exchange and waits for the transports to
// come up.
fn negotiate_dial(mut conn Conn, mut signaling Signaling, mut pump SignalPump, config DialConfig, deadline time.Time, log logging.Logger) ! {
	offer := conn.pc.create_offer()!
	mut sdp_text := offer.sdp
	if identity := config.identity {
		sdp_text = inject_identity(sdp_text, identity.sign(sdp_text)!)
	}
	// Gathering starts here, so everything that needs candidates comes after.
	conn.pc.set_local_description(webrtc.SessionDescription{
		typ: .offer
		sdp: sdp_text
	})!

	ufrag := media_attribute(sdp_text, 'ice-ufrag') or {
		return error('nethernet: the local offer carries no ICE credentials')
	}

	mut offered := sdp_text
	disable_trickle := config.disable_trickle_ice || signaling.disable_trickle_ice()
	if disable_trickle {
		// Nothing will carry candidates later, so gathering has to finish before
		// the offer goes out.
		offered = embed_candidates(sdp_text, conn.gather_candidates(ufrag, config.timeout)!)
	}

	signaling.signal(Signal{
		typ:           signal_type_offer
		connection_id: conn.id
		data:          offered
		network_id:    conn.network_id
	})!

	await_answer(mut conn, pump.collector, config, deadline, log)!
	log.debug('answer applied, waiting for the transports')

	// Trickling starts only now, after the answer is in place. A candidate sent
	// earlier lets the server begin connectivity checks against an agent that
	// does not yet know the credentials to authenticate them with; it answers
	// those checks without a MESSAGE-INTEGRITY the server will accept, and the
	// pair the server settles on never recovers.
	if !disable_trickle {
		mut trickler := &CandidateTrickler{
			conn:      conn
			signaling: signaling
			ufrag:     ufrag
			log:       log
		}
		spawn trickler.run()
	}

	// From here the pump owns the queue: the candidates the server trickles have
	// to reach ICE while it is still checking.
	spawn pump.run()

	remaining := deadline - time.now()
	if remaining <= 0 {
		return error('nethernet: negotiation timed out waiting for the transports')
	}
	conn.pc.wait_connected(remaining)!
}

// await_answer waits for the server's answer and applies it, handling the
// candidates and errors that arrive alongside.
fn await_answer(mut conn Conn, collector &SignalCollector, config DialConfig, deadline time.Time, log logging.Logger) ! {
	// A server starts trickling as soon as it has sent the answer, so its
	// candidates can overtake it. They are held until the answer is applied:
	// ICE cannot check a candidate before it knows the credentials to
	// authenticate the check with, and one added early is one wasted.
	mut early := []string{}

	for time.now() < deadline {
		sig := collector.next(signal_poll_interval) or { continue }

		match sig.typ {
			signal_type_answer {
				apply_answer(mut conn, sig.data, config)!
				for candidate in early {
					conn.pc.add_ice_candidate(candidate) or {
						log.debug('discarding candidate: ${err.msg()}')
					}
				}
				return
			}
			signal_type_candidate {
				early << sig.data
			}
			signal_type_error {
				return error('nethernet: peer reported error code ${sig.data}')
			}
			else {
				log.debug('ignoring signal of type "${sig.typ}"')
			}
		}
	}
	return error('nethernet: negotiation timed out waiting for an answer')
}

// apply_answer verifies the server's identity and applies its description.
fn apply_answer(mut conn Conn, sdp_text string, config DialConfig) ! {
	if identity := extract_identity(sdp_text) {
		conn.public_key = verify_server_identity(identity, sdp_text)!
		conn.remote_domain = identity.domain
	} else if !config.allow_identityless_server {
		// Without an assertion nothing ties the answer to a known server, so
		// whoever intercepted the offer could have answered it.
		return error('nethernet: the answer carries no identity assertion')
	}

	conn.pc.set_remote_description(webrtc.SessionDescription{
		typ: .answer
		sdp: sdp_text
	})!

	// A server that cannot trickle puts its candidates in the answer.
	for candidate in description_candidates(sdp_text) {
		conn.pc.add_ice_candidate(candidate) or { continue }
	}
}

// verify_server_identity checks the server's token and the assertion made under
// it.
//
// The token is self-signed: it proves the server holds the key it names, and
// nothing more. Trusting it is trust on first use - a caller that knows which
// key to expect should compare it against the one this returns.
fn verify_server_identity(identity IdentityData, sdp_text string) !ecdsa.PublicKey {
	public_key := claim_public_key(identity.token, true) or {
		return error('nethernet: verify server token: ${err.msg()}')
	}
	identity.verify(sdp_text, public_key)!
	return public_key
}

// dial_error_code maps a failed dial onto the code the peer is told about.
fn dial_error_code(err IError) int {
	message := err.msg()
	if message.contains('identity') || message.contains('token') {
		return error_code_identity_verification_failed
	}
	if message.contains('timed out') {
		return error_code_negotiation_timeout_waiting_for_response
	}
	return error_code_failed_to_create_offer
}

// signal_error tells the peer why the connection is not happening. It is best
// effort: the dial has already failed, and failing to report it changes
// nothing.
fn signal_error(mut signaling Signaling, network_id string, connection_id u64, code int) {
	signaling.signal(Signal{
		typ:           signal_type_error
		connection_id: connection_id
		data:          code.str()
		network_id:    network_id
	}) or {}
}

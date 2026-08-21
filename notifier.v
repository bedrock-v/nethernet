module nethernet

import sync
import time
import webrtc.logging

// signal_queue_size bounds how many signals may be waiting to be handled.
// Candidates arrive in bursts while ICE gathers, and dropping one costs a
// candidate pair.
const signal_queue_size = 64

// signal_poll_interval is how long a reader waits on the queue before checking
// whether it should still be running.
const signal_poll_interval = 50 * time.millisecond

// SignalCollector receives the signals belonging to one connection.
//
// A signalling channel broadcasts every signal to every subscriber, so the
// filter here is what keeps one connection's candidates out of another's queue.
struct SignalCollector {
	// connection_id and network_id are the pair a signal must match. Together
	// they identify one connection between two networks.
	connection_id u64
	network_id    string
mut:
	signals chan Signal
	log     logging.Logger = logging.nop()
}

// notify_signal queues a signal for this connection.
fn (mut c SignalCollector) notify_signal(sig Signal) bool {
	if sig.connection_id != c.connection_id || sig.network_id != c.network_id {
		return false
	}
	select {
		c.signals <- sig {
			return true
		}
		else {
			// Blocking here would stall the signalling channel's read loop for
			// every other connection too.
			c.log.warn('dropping ${sig.typ} signal: the queue for connection ${c.connection_id} is full')
			return false
		}
	}
	return false
}

// next returns the next signal, waiting up to timeout for one.
fn (c &SignalCollector) next(timeout time.Duration) ?Signal {
	mut sig := Signal{}
	select {
		sig = <-c.signals {
			return sig
		}
		timeout {
			return none
		}
	}
	return none
}

// SignalPump applies incoming signals to an established connection.
//
// Negotiation is over by the time it runs, so what arrives is candidates - ICE
// keeps looking for a better path after the connection is usable - and the
// error signal that says the peer has given up.
struct SignalPump {
mut:
	conn      &Conn            = unsafe { nil }
	collector &SignalCollector = unsafe { nil }
	log       logging.Logger   = logging.nop()

	// signaling and subscription are released when the pump stops, so a closed
	// connection stops being notified.
	signaling    Signaling
	subscription int
	released     bool

	stopped bool
	stop_mu &sync.Mutex = sync.new_mutex()
}

// run handles signals until the connection closes.
fn (mut p SignalPump) run() {
	for !p.is_stopped() {
		mut conn := p.conn
		if conn.is_closed() {
			break
		}
		sig := p.collector.next(signal_poll_interval) or { continue }
		conn.handle_signal(sig) or { p.log.debug('handling ${sig.typ} signal: ${err.msg()}') }
	}
	p.release()
}

// stop ends the pump.
fn (mut p SignalPump) stop() {
	p.stop_mu.lock()
	p.stopped = true
	p.stop_mu.unlock()
}

fn (mut p SignalPump) is_stopped() bool {
	p.stop_mu.lock()
	defer {
		p.stop_mu.unlock()
	}
	return p.stopped
}

// release unsubscribes from the signalling channel, once.
fn (mut p SignalPump) release() {
	p.stop_mu.lock()
	defer {
		p.stop_mu.unlock()
	}
	if p.released {
		return
	}
	p.released = true
	p.signaling.stop_notify(p.subscription)
}

// CandidateTrickler signals local candidates to the peer as ICE gathers them.
//
// The WebRTC stack accumulates candidates rather than calling back, so this
// polls. It runs in its own thread because signalling must never hold up
// gathering: an ICE agent whose gatherer is blocked can fail the connection.
struct CandidateTrickler {
mut:
	conn      &Conn = unsafe { nil }
	signaling Signaling
	// ufrag is the local ICE username fragment. The game's parser expects every
	// candidate to name the credentials it belongs to.
	ufrag string
	log   logging.Logger = logging.nop()
}

fn (mut t CandidateTrickler) run() {
	mut conn := t.conn
	mut sent := 0
	mut idle := time.Duration(0)

	for !conn.is_closed() && !t.signaling.is_closed() {
		candidates := conn.pc.local_candidates()
		if candidates.len == sent {
			// Gathering has a long tail - a relayed candidate can take seconds -
			// but it does end, and a thread that never returns is a leak.
			idle += candidate_poll_interval
			if idle >= candidate_gather_timeout {
				return
			}
			time.sleep(candidate_poll_interval)
			continue
		}
		idle = 0

		for index in sent .. candidates.len {
			t.signaling.signal(Signal{
				typ:           signal_type_candidate
				connection_id: conn.id
				data:          format_ice_candidate(index, candidates[index], t.ufrag)
				network_id:    conn.network_id
			}) or {
				t.log.error('signalling candidate: ${err.msg()}')
				conn.close_with('signal candidate: ${err.msg()}')
				return
			}
		}
		sent = candidates.len
	}
}

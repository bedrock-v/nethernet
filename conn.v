module nethernet

import crypto.ecdsa
import sync
import time
import bedrock_v.webrtc

// MessageReliability selects which of a connection's two data channels a
// message travels on.
pub enum MessageReliability {
	// reliable preserves order and retransmits. The game uses it for
	// everything.
	reliable
	// unreliable gives up after the first attempt. Vanilla opens the channel but
	// appears never to use it, and a dropped segment would leave a multi-segment
	// message unfinishable, so a message sent here must fit in one segment.
	unreliable
}

// label is the data channel name the game gives this reliability.
pub fn (r MessageReliability) label() string {
	return match r {
		.reliable { 'ReliableDataChannel' }
		.unreliable { 'UnreliableDataChannel' }
	}
}

// options are the data channel parameters for this reliability. A channel the
// peer opened has to match them, or it is not the channel we expect.
pub fn (r MessageReliability) options() webrtc.DataChannelOptions {
	return match r {
		.reliable {
			webrtc.DataChannelOptions{
				ordered: true
			}
		}
		.unreliable {
			webrtc.DataChannelOptions{
				max_retransmits: u16(0)
			}
		}
	}
}

// matches reports whether a channel the peer opened carries this reliability.
fn (r MessageReliability) matches(mut channel webrtc.DataChannel) bool {
	if channel.label != r.label() {
		return false
	}
	return match r {
		.reliable { channel.reliable() && channel.ordered() }
		.unreliable { !channel.reliable() }
	}
}

// max_segments is what the one-byte counter allows: it starts at
// total - 1 and counts down to zero.
const max_segments = 256

// default_read_timeout bounds a read that was given no deadline. It is long
// enough that an idle connection is not mistaken for a dead one.
const default_read_timeout = 30 * time.second

// Conn is one NetherNet peer connection.
//
// Underneath is a WebRTC peer connection with two data channels. Messages
// larger than a single channel message are split into segments, each prefixed
// with the number of segments still to come, and reassembled on the way in.
//
// A Conn may be sent to from several threads. Reading is single-consumer: the
// reassembly buffer belongs to whichever thread is reading.
pub struct Conn {
mut:
	pc         &webrtc.PeerConnection = unsafe { nil }
	reliable   &webrtc.DataChannel    = unsafe { nil }
	unreliable &webrtc.DataChannel    = unsafe { nil }

	// inbound holds the segments received so far for each channel, and the
	// counter the next segment must carry.
	inbound [2]Reassembler

	// read_buf is what remains of the last message read, for the byte-oriented
	// read.
	read_buf []u8

	// send_mu keeps the segments of one message together on the wire. Without
	// it, two threads sending at once would interleave and neither message would
	// reassemble.
	send_mu &sync.Mutex = sync.new_mutex()

	closed     bool
	close_mu   &sync.Mutex = sync.new_mutex()
	close_note string

	// public_key is the identity the peer proved, when it presented one.
	public_key    ?ecdsa.PublicKey
	remote_domain string

	// on_close is called once when the connection closes, so a listener can
	// forget it.
	on_close fn (mut c Conn) = unsafe { nil }
pub:
	// id is the connection ID both ends use to reference this connection in
	// signals.
	id u64
	// network_id and local_network_id name the remote and local networks.
	network_id       string
	local_network_id string
}

// Reassembler collects the segments of one message.
struct Reassembler {
mut:
	// remaining is the counter the last segment carried. While it is above zero,
	// more segments are expected.
	remaining u8
	started   bool
	data      []u8
}

// public_key returns the identity the peer proved during negotiation.
//
// The peer signed this connection's DTLS fingerprints with the matching private
// key, so the key is bound to this connection and not merely presented on it.
// It is none when the peer connected without an identity assertion.
pub fn (c &Conn) public_key() ?ecdsa.PublicKey {
	return c.public_key
}

// identity_domain is the identity provider the peer's token came from, when it
// presented one.
pub fn (c &Conn) identity_domain() string {
	return c.remote_domain
}

// read_packet returns the next whole message from the reliable channel.
//
// The game's decoder reads one packet at a time, so this is the method to use;
// read exists for callers that want a byte stream.
pub fn (mut c Conn) read_packet() ![]u8 {
	return c.receive(.reliable, default_read_timeout)!
}

// read fills b from the reliable channel, keeping whatever does not fit for the
// next call.
pub fn (mut c Conn) read(mut b []u8) !int {
	if c.read_buf.len == 0 {
		c.read_buf = c.receive(.reliable, default_read_timeout)!
	}
	n := if b.len < c.read_buf.len { b.len } else { c.read_buf.len }
	for i in 0 .. n {
		b[i] = c.read_buf[i]
	}
	c.read_buf = c.read_buf[n..].clone()
	return n
}

// receive returns the next whole message from one of the channels, waiting up
// to timeout for it.
//
// The timeout bounds the whole message, not one segment: a message split into
// segments that keep arriving stays within it as long as each segment does.
pub fn (mut c Conn) receive(reliability MessageReliability, timeout time.Duration) ![]u8 {
	if c.is_closed() {
		return error('nethernet: connection closed${c.close_reason()}')
	}
	mut channel := c.channel(reliability)!

	for {
		message := channel.recv(timeout) or {
			// A closed channel is the connection ending, not a read failing.
			if c.is_closed() {
				return error('nethernet: connection closed${c.close_reason()}')
			}
			return err
		}
		payload, complete := c.accept_segment(reliability, message.data) or {
			// A message that cannot be reassembled leaves a partial buffer that
			// nothing will ever complete, so the connection ends rather than
			// carrying on with a peer that is either broken or hostile.
			c.close_with(err.msg())
			return err
		}
		if complete {
			return payload
		}
	}
	return error('nethernet: unreachable')
}

// accept_segment adds one received segment to the reassembly buffer. It reports
// the message and true once the last segment has arrived, and false while more
// are still expected.
fn (mut c Conn) accept_segment(reliability MessageReliability, data []u8) !([]u8, bool) {
	if data.len < 2 {
		return error('nethernet: message of ${data.len} bytes carries no payload')
	}
	remaining := data[0]
	if reliability == .unreliable && remaining > 0 {
		return error('nethernet: segmented message on ${reliability.label()}')
	}

	index := int(reliability)
	mut state := &c.inbound[index]
	if state.started && state.remaining - 1 != remaining {
		// A segment out of sequence means the message can never be completed,
		// and going on would splice unrelated bytes together.
		return error('nethernet: expected segment counter ${state.remaining - 1}, got ${remaining}')
	}
	state.remaining = remaining
	state.started = true
	state.data << data[1..]

	if remaining > 0 {
		return []u8{}, false
	}
	payload := state.data
	state.data = []u8{}
	state.started = false
	return payload, true
}

// write sends b over the reliable channel.
pub fn (mut c Conn) write(b []u8) !int {
	return c.send(b, .reliable)
}

// send writes a message to one of the channels, splitting it into segments when
// it does not fit in one.
//
// Each segment is prefixed with the number of segments still to come, counting
// down to zero on the last. The counter is one byte, so a message spans at most
// 256 segments.
pub fn (mut c Conn) send(data []u8, reliability MessageReliability) !int {
	if c.is_closed() {
		return error('nethernet: connection closed${c.close_reason()}')
	}
	if reliability == .unreliable && data.len > max_message_size {
		return error('nethernet: ${data.len} bytes cannot be sent over ${reliability.label()}, which does not segment')
	}
	mut channel := c.channel(reliability)!

	total := if data.len == 0 { 1 } else { (data.len + max_message_size - 1) / max_message_size }
	if total > max_segments {
		return error('nethernet: ${data.len} bytes need ${total} segments, more than ${max_segments}')
	}

	c.send_mu.lock()
	defer {
		c.send_mu.unlock()
	}

	mut written := 0
	for index in 0 .. total {
		start := index * max_message_size
		mut end := start + max_message_size
		if end > data.len {
			end = data.len
		}
		mut segment := [u8(total - 1 - index)]
		segment << data[start..end]
		channel.send(segment, false) or {
			return error('nethernet: write segment ${index + 1} of ${total}: ${err.msg()}')
		}
		written += end - start
	}
	return written
}

// latency is the current round trip time to the peer, halved.
pub fn (mut c Conn) latency() time.Duration {
	if pair := c.pc.selected_candidate_pair() {
		return time.Duration(pair.round_trip_time / 2)
	}
	return 0
}

// local_addr is this end of the connection, with the candidates gathered for
// it.
pub fn (mut c Conn) local_addr() Addr {
	mut addr := Addr{
		connection_id: c.id
		network_id:    c.local_network_id
		candidates:    c.pc.local_candidates()
	}
	if pair := c.pc.selected_candidate_pair() {
		addr.selected_candidate = pair.local.str()
	}
	return addr
}

// remote_addr is the peer end of the connection.
pub fn (mut c Conn) remote_addr() Addr {
	mut addr := Addr{
		connection_id: c.id
		network_id:    c.network_id
	}
	if pair := c.pc.selected_candidate_pair() {
		addr.selected_candidate = pair.remote.str()
	}
	return addr
}

// batch_header returns nothing: NetherNet prefixes no header before a batch of
// game packets, unlike RakNet.
pub fn (c &Conn) batch_header() []u8 {
	return []u8{}
}

// disable_encryption reports that the game protocol must not encrypt on top of
// this connection.
//
// DTLS already encrypts every byte, so a second layer buys nothing. It does
// mean the protocol layer loses the replay protection its own encryption gives
// it: a server should confirm the player really joined the Xbox Live session
// rather than trusting the Login packet alone.
pub fn (c &Conn) disable_encryption() bool {
	return true
}

// is_closed reports whether the connection has been closed, by either end.
pub fn (mut c Conn) is_closed() bool {
	c.close_mu.lock()
	defer {
		c.close_mu.unlock()
	}
	if c.closed {
		return true
	}
	return c.pc.connection_state() in [.closed, .failed]
}

fn (c &Conn) close_reason() string {
	return if c.close_note == '' { '' } else { ': ${c.close_note}' }
}

// close shuts the connection down. It is safe to call more than once.
pub fn (mut c Conn) close() {
	c.close_with('')
}

// close_with closes the connection and records why, so a read or a send that
// comes after can say what happened.
fn (mut c Conn) close_with(note string) {
	c.close_mu.lock()
	if c.closed {
		c.close_mu.unlock()
		return
	}
	c.closed = true
	if note != '' {
		c.close_note = note
	}
	c.close_mu.unlock()

	if c.reliable != unsafe { nil } {
		c.reliable.close()
	}
	if c.unreliable != unsafe { nil } {
		c.unreliable.close()
	}
	c.pc.close()

	if c.on_close != unsafe { nil } {
		handler := c.on_close
		handler(mut c)
	}
}

// channel returns the data channel for a reliability, once it exists.
fn (mut c Conn) channel(reliability MessageReliability) !&webrtc.DataChannel {
	channel := match reliability {
		.reliable { c.reliable }
		.unreliable { c.unreliable }
	}
	if channel == unsafe { nil } {
		return error('nethernet: ${reliability.label()} was never opened')
	}
	return channel
}

// handle_signal applies a signal that arrived for an established connection.
//
// Only candidates and errors turn up at this point: the offer and the answer
// were handled while the connection was still being negotiated.
fn (mut c Conn) handle_signal(sig Signal) ! {
	match sig.typ {
		signal_type_candidate {
			c.pc.add_ice_candidate(sig.data) or {
				return error('nethernet: add remote candidate: ${err.msg()}')
			}
		}
		signal_type_error {
			c.close_with('peer reported error code ${sig.data}')
		}
		else {
			return error('nethernet: unexpected signal type "${sig.typ}"')
		}
	}
}

// candidate_poll_interval is how often gathered candidates are collected. It is
// short enough that the first host candidate is signalled almost at once.
const candidate_poll_interval = 100 * time.millisecond

// candidate_gather_timeout is how long gathering may produce nothing before it
// is taken to be finished.
const candidate_gather_timeout = 10 * time.second

// gather_candidates waits for gathering to settle and returns every candidate,
// for a peer that cannot accept them one at a time.
fn (mut c Conn) gather_candidates(ufrag string, timeout time.Duration) ![]string {
	deadline := time.now().add(timeout)
	mut count := 0
	mut idle := time.Duration(0)
	for time.now() < deadline {
		candidates := c.pc.local_candidates()
		if candidates.len == count && count > 0 {
			idle += candidate_poll_interval
			if idle >= candidate_settle_time {
				break
			}
		} else {
			idle = 0
			count = candidates.len
		}
		time.sleep(candidate_poll_interval)
	}

	candidates := c.pc.local_candidates()
	if candidates.len == 0 {
		return error('nethernet: no local candidates were gathered')
	}
	mut out := []string{cap: candidates.len}
	for index, candidate in candidates {
		out << format_ice_candidate(index, candidate, ufrag)
	}
	return out
}

// candidate_settle_time is how long gathering must be quiet before the set of
// candidates is taken to be complete.
const candidate_settle_time = 2 * time.second

module discovery

import nethernet
import net
import rand
import sync
import time
import bedrock_v.webrtc.logging

// default_port is the port Minecraft uses for LAN discovery. A server has to
// listen on it to be found; a client may use any port, and should when the game
// itself already holds 7551.
pub const default_port = 7551

// max_datagram_size is the largest UDP payload, which is also the most a
// discovery packet may be.
const max_datagram_size = 65535

// address_lifetime is how long a network's address is remembered after it last
// sent anything. A peer that has gone quiet for this long is no longer somewhere
// to send a signal.
const address_lifetime = 15 * time.second

// ListenConfig configures a discovery Listener.
@[params]
pub struct ListenConfig {
pub:
	// network_id is the NetherNet network this listener speaks for. Zero picks a
	// random one, which is right for a client and wrong for a server that wants
	// to be recognised across restarts.
	network_id u64
	// broadcast_address is where requests go looking for servers. Empty uses the
	// limited broadcast address on the default port.
	broadcast_address string
	// broadcast_interval is how often a request goes out, and how often stale
	// addresses are forgotten.
	broadcast_interval time.Duration = 2 * time.second
	// broadcast disables sending requests when false, which is what a server
	// wants: it answers requests rather than making them.
	broadcast bool           = true
	logger    logging.Logger = logging.nop()
}

// Listener is the LAN signalling channel.
//
// It is a NetherNet Signaling implementation: the same UDP socket that finds
// games carries the offers, answers and candidates that negotiate a connection
// to one. Pass it to nethernet.listen to host, or to nethernet.dial to join.
pub struct Listener {
mut:
	conn   &net.UdpConn = unsafe { nil }
	config ListenConfig
	log    logging.Logger

	// id is the local network ID. It is what a remote peer names to reach this
	// listener.
	id u64

	// addresses maps a network ID to the UDP address its packets come from,
	// which is how a signal addressed to a network ID finds somewhere to go.
	addresses    map[u64]RemoteAddress
	addresses_mu &sync.RwMutex = sync.new_rwmutex()

	// notifiers are the subscriptions signals are delivered to. The count only
	// ever rises, so an ID is never reused and a stale unsubscribe cannot cancel
	// somebody else's subscription.
	notifiers    map[int]nethernet.Notifier
	notify_count int
	notifiers_mu &sync.RwMutex = sync.new_rwmutex()

	// responses holds the last advertisement seen from each server, for a client
	// listing games.
	responses    map[u64][]u8
	responses_mu &sync.RwMutex = sync.new_rwmutex()

	// response_data is the advertisement this listener answers requests with. It
	// is empty until a server sets one, and a request is ignored until then.
	response_data []u8
	response_mu   &sync.RwMutex = sync.new_rwmutex()

	closed   bool
	close_mu &sync.Mutex = sync.new_mutex()
}

// RemoteAddress is where a network was last heard from.
struct RemoteAddress {
	addr net.Addr
	// seen is when the last packet arrived, so an address that has gone quiet
	// can be dropped.
	seen time.Time
}

// listen starts a discovery listener bound to addr.
//
// A server should bind ':7551' so clients broadcasting there reach it. A client
// may pass an empty address for an ephemeral port, which is what it wants when
// the game already holds the default one.
pub fn listen(addr string, config ListenConfig) !&Listener {
	mut bind := addr
	if bind == '' {
		bind = ':0'
	}
	// The default port is often already held - by the game itself, most of the
	// time - and the raw errno that comes back does not say which address failed.
	mut conn := net.listen_udp(bind) or { return error('discovery: binding ${bind}: ${err.msg()}') }
	conn.sock.set_option_bool(.broadcast, true) or {
		conn.close() or {}
		return error('discovery: enabling broadcast: ${err.msg()}')
	}

	mut id := config.network_id
	if id == 0 {
		id = rand.u64()
	}

	mut l := &Listener{
		conn:   conn
		config: config
		log:    config.logger.with_scope('nethernet/discovery')
		id:     id
	}
	spawn l.run()
	spawn l.background()
	return l
}

// network_id is the local network ID, in the string form NetherNet uses.
pub fn (l &Listener) network_id() string {
	return l.id.str()
}

// id returns the local network ID as a number, which is how discovery packets
// carry it.
pub fn (l &Listener) id() u64 {
	return l.id
}

// disable_trickle_ice reports false: a LAN peer can carry candidates at any
// time, so there is no reason to make it wait for gathering.
pub fn (l &Listener) disable_trickle_ice() bool {
	return false
}

// credentials returns no ICE servers. Every peer on a local network is directly
// reachable, so there is nothing for STUN or TURN to do.
pub fn (mut l Listener) credentials() !nethernet.Credentials {
	if l.is_closed() {
		return error('discovery: listener closed')
	}
	return nethernet.Credentials{}
}

// signal sends a NetherNet signal to the network it is addressed to.
pub fn (mut l Listener) signal(sig nethernet.Signal) ! {
	if l.is_closed() {
		return error('discovery: listener closed')
	}
	recipient := sig.network_id.u64()
	if recipient == 0 {
		return error('discovery: "${sig.network_id}" is not a network ID')
	}

	l.addresses_mu.@rlock()
	remote := l.addresses[recipient] or {
		l.addresses_mu.runlock()
		// Nothing has been heard from this network, so there is no address to
		// send to. On a LAN that means it has not broadcast recently.
		return error('discovery: no address is known for network ${recipient}')
	}
	l.addresses_mu.runlock()

	l.write(MessagePacket{
		recipient_id: recipient
		data:         sig.str()
	}, remote.addr)!
}

// notify subscribes n to incoming signals and returns the subscription ID.
pub fn (mut l Listener) notify(n nethernet.Notifier) int {
	l.notifiers_mu.@lock()
	defer {
		l.notifiers_mu.unlock()
	}
	id := l.notify_count
	l.notifiers[id] = n
	l.notify_count++
	return id
}

// stop_notify cancels a subscription.
pub fn (mut l Listener) stop_notify(id int) {
	l.notifiers_mu.@lock()
	l.notifiers.delete(id)
	l.notifiers_mu.unlock()
}

// pong_data sets what this listener advertises, from a RakNet pong response.
pub fn (mut l Listener) pong_data(data []u8) {
	server := ServerData.from_pong(data) or {
		l.log.error('reading pong data: ${err.msg()}')
		return
	}
	l.set_server_data(server)
}

// set_server_data sets what this listener advertises to clients looking for
// games.
pub fn (mut l Listener) set_server_data(data ServerData) {
	encoded := data.encode()
	l.response_mu.@lock()
	l.response_data = encoded
	l.response_mu.unlock()
}

// responses returns the advertisement last seen from each server on the
// network, keyed by network ID. A client dials the ID it picked.
pub fn (mut l Listener) responses() map[u64][]u8 {
	l.responses_mu.@rlock()
	defer {
		l.responses_mu.runlock()
	}
	return l.responses.clone()
}

// servers returns the responses decoded, dropping any this version cannot read.
pub fn (mut l Listener) servers() map[u64]ServerData {
	mut out := map[u64]ServerData{}
	for network_id, data in l.responses() {
		out[network_id] = ServerData.decode(data) or { continue }
	}
	return out
}

// is_closed reports whether the listener has been closed.
pub fn (mut l Listener) is_closed() bool {
	l.close_mu.lock()
	defer {
		l.close_mu.unlock()
	}
	return l.closed
}

// close stops the listener and drops every subscription.
pub fn (mut l Listener) close() {
	l.close_mu.lock()
	if l.closed {
		l.close_mu.unlock()
		return
	}
	l.closed = true
	l.close_mu.unlock()

	l.conn.close() or {}

	l.notifiers_mu.@lock()
	l.notifiers.clear()
	l.notifiers_mu.unlock()
}

// run reads packets until the listener is closed.
fn (mut l Listener) run() {
	mut buf := []u8{len: max_datagram_size}
	l.conn.set_read_timeout(read_timeout)

	for !l.is_closed() {
		count, addr := l.conn.read(mut buf) or {
			// A timeout is how the loop gets a chance to notice closure; every
			// other error means the socket is gone.
			if err.code() == net.err_timed_out_code {
				continue
			}
			if !l.is_closed() {
				l.log.error('reading from the socket: ${err.msg()}')
				l.close()
			}
			return
		}
		l.handle(buf[..count].clone(), addr) or {
			l.log.debug('handling a packet from ${addr}: ${err.msg()}')
		}
	}
}

// read_timeout is how long a read waits before the loop checks whether the
// listener has been closed.
const read_timeout = 500 * time.millisecond

// handle decodes one packet and acts on it.
fn (mut l Listener) handle(data []u8, addr net.Addr) ! {
	pk, sender_id := unmarshal(data)!
	if sender_id == l.id {
		// Broadcasts come back to the sender; answering our own request would
		// list us as a server to ourselves.
		return
	}
	l.remember(sender_id, addr)

	match pk {
		RequestPacket {
			l.answer_request(addr)!
		}
		ResponsePacket {
			l.responses_mu.@lock()
			l.responses[sender_id] = pk.application_data
			l.responses_mu.unlock()
		}
		MessagePacket {
			l.deliver(pk, sender_id)!
		}
	}
}

// remember records where a network was last heard from, so a signal addressed
// to it has somewhere to go.
fn (mut l Listener) remember(network_id u64, addr net.Addr) {
	l.addresses_mu.@lock()
	l.addresses[network_id] = RemoteAddress{
		addr: addr
		seen: time.now()
	}
	l.addresses_mu.unlock()
}

// answer_request replies to a client looking for games, when there is something
// to advertise.
fn (mut l Listener) answer_request(addr net.Addr) ! {
	l.response_mu.@rlock()
	data := l.response_data.clone()
	l.response_mu.runlock()

	if data.len == 0 {
		// Nothing has been advertised yet, so this is a client rather than a
		// server and there is nothing to say.
		return
	}
	l.write(ResponsePacket{
		application_data: data
	}, addr)!
}

// deliver hands a signal to every subscriber.
fn (mut l Listener) deliver(pk MessagePacket, sender_id u64) ! {
	if pk.recipient_id != l.id {
		return
	}
	// The game sends "Ping" as a keep-alive on this channel. It is not a signal
	// and does not parse as one.
	if pk.data == '' || pk.data == 'Ping' {
		return
	}

	mut sig := nethernet.Signal.parse(pk.data)!
	sig.network_id = sender_id.str()

	l.notifiers_mu.@rlock()
	mut notifiers := []nethernet.Notifier{cap: l.notifiers.len}
	for _, n in l.notifiers {
		notifiers << n
	}
	l.notifiers_mu.runlock()

	for mut n in notifiers {
		n.notify_signal(sig)
	}
}

// write encodes a packet and sends it.
fn (mut l Listener) write(pk Packet, addr net.Addr) ! {
	l.conn.write_to(addr, marshal(pk, l.id))!
}

// background broadcasts requests and forgets addresses that have gone quiet.
fn (mut l Listener) background() {
	for !l.is_closed() {
		time.sleep(l.config.broadcast_interval)
		if l.is_closed() {
			return
		}
		l.forget_stale_addresses()

		if !l.config.broadcast {
			continue
		}
		l.broadcast_request() or {
			if !l.is_closed() {
				l.log.debug('broadcasting a request: ${err.msg()}')
			}
		}
	}
}

// broadcast_request asks every server on the network to describe itself.
fn (mut l Listener) broadcast_request() ! {
	mut target := l.config.broadcast_address
	if target == '' {
		target = '255.255.255.255:${default_port}'
	}
	addresses := net.resolve_addrs(target, .ip, .udp)!
	if addresses.len == 0 {
		return error('discovery: "${target}" resolved to no address')
	}
	l.write(RequestPacket{}, addresses[0])!
}

// forget_stale_addresses drops the networks that have stopped sending. Keeping
// them would mean signalling into an address nothing is listening on.
fn (mut l Listener) forget_stale_addresses() {
	now := time.now()
	l.addresses_mu.@lock()
	for network_id, remote in l.addresses.clone() {
		if now - remote.seen > address_lifetime {
			l.addresses.delete(network_id)
		}
	}
	l.addresses_mu.unlock()
}

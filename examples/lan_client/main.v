// A client that finds servers on the local network, connects to the first one
// and sends it a message.
module main

import nethernet
import nethernet.discovery
import os
import time
import webrtc.ice
import webrtc.logging

fn main() {
	log := logging.default('example', .info)

	// A client binds an ephemeral port: the default one is often already held by
	// the game itself, and a client only needs to be able to receive replies.
	// Pass an address as the first argument to broadcast somewhere specific,
	// which is how this reaches a server on the same machine.
	mut signaling := discovery.listen('',
		broadcast_address: os.args[1] or { '' }
		logger:            logging.from_env('discovery')
	)!
	defer {
		signaling.close()
	}

	network_id, server := discover(mut signaling, 10 * time.second) or {
		log.error(err.msg())
		exit(1)
	}
	log.info('found "${server.level_name}" by ${server.server_name} on ${server.version} (network ${network_id})')

	mut conn := nethernet.dial(network_id.str(), mut signaling,
		interfaces: interface_filter()
		logger:     logging.from_env('nethernet')
	)!
	defer {
		conn.close()
	}
	log.info('connected to ${conn.remote_addr()}')

	conn.write('hello from V'.bytes())!
	reply := conn.read_packet()!
	log.info('server replied: ${reply.bytestr()}')
}

// discover waits for the first server to answer a broadcast.
fn discover(mut signaling discovery.Listener, timeout time.Duration) !(u64, discovery.ServerData) {
	deadline := time.now().add(timeout)
	for time.now() < deadline {
		for network_id, server in signaling.servers() {
			// Anything answering here is a NetherNet host: LAN discovery carries
			// nothing else.
			return network_id, server
		}
		time.sleep(200 * time.millisecond)
	}
	return error('no server answered within ${timeout.milliseconds()}ms')
}

// interface_filter narrows ICE to one interface when NETHERNET_INTERFACE names
// one. On a host with several - a docker bridge alongside the real network -
// the two ends can otherwise settle on candidate pairs that cannot reach each
// other.
fn interface_filter() ice.InterfaceOptions {
	name := os.getenv('NETHERNET_INTERFACE')
	if name == '' {
		return ice.InterfaceOptions{}
	}
	return ice.InterfaceOptions{
		interfaces:       [name]
		include_loopback: name == 'lo'
	}
}

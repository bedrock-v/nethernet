// A server that advertises itself on the local network and echoes back
// whatever a client sends.
//
// Run it, then run examples/lan_client.
module main

import nethernet
import nethernet.discovery
import os
import time
import bedrock_v.webrtc.ice
import bedrock_v.webrtc.logging

const network_id = u64(1122334455)

fn main() {
	log := logging.default('example', .info)

	// The discovery listener is both the game list and the signalling channel.
	// A server binds the default port so clients broadcasting there find it, and
	// does not broadcast itself: it answers requests rather than making them.
	//
	// Pass an address as the first argument to bind somewhere else. That is worth
	// doing when the game itself is running on this machine, because it holds the
	// default port and the bind will fail.
	mut signaling := discovery.listen(os.args[1] or { ':${discovery.default_port}' },
		network_id: network_id
		broadcast:  false
		logger:     logging.from_env('discovery')
	)!
	signaling.set_server_data(discovery.ServerData{
		server_name:      'Vedrock'
		protocol:         800
		version:          '1.21.0'
		level_name:       'Vedrock level'
		game_type:        discovery.game_type_creative
		max_player_count: 10
	})

	// allow_anonymous lets in clients that present no identity, which is what an
	// offline LAN client does. A server open to the internet should leave it off
	// and check the identity the client proves.
	mut listener := nethernet.listen(mut signaling,
		allow_anonymous: true
		interfaces:      interface_filter()
		logger:          logging.from_env('nethernet')
	)!
	log.info('listening as network ${listener.network_id}')

	for {
		mut conn := listener.accept(1 * time.hour) or {
			log.error('accepting: ${err.msg()}')
			continue
		}
		spawn echo(mut conn, log)
	}
}

fn echo(mut conn nethernet.Conn, log logging.Logger) {
	log.info('connection from ${conn.remote_addr()}')
	defer {
		conn.close()
	}

	for {
		packet := conn.read_packet() or {
			log.info('connection closed: ${err.msg()}')
			return
		}
		log.info('received ${packet.len} bytes: ${packet.bytestr()}')
		conn.write(packet) or {
			log.error('echoing: ${err.msg()}')
			return
		}
	}
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

module discovery

import nethernet
import time
import os
import bedrock_v.webrtc.ice
import bedrock_v.webrtc.logging

// The whole stack, both ends in one process: LAN discovery finds the server,
// the same socket carries the offer and the answer, and the peer connection
// that comes out of it moves a message in each direction.
//
// It runs over loopback with the interface filter narrowed to it. A host with
// several interfaces - a docker bridge, say - can otherwise have the two ends
// settle on candidate pairs that cannot reach each other, which is a property
// of the network rather than of this code.

const test_port = 17551

const test_network_id = u64(998877)

// loopback_name is what the loopback interface is called here. The BSDs number
// it, Linux does not.
const loopback_name = $if macos {
	'lo0'
} $else $if freebsd || openbsd || netbsd || dragonfly {
	'lo0'
} $else {
	'lo'
}

const loopback_only = ice.InterfaceOptions{
	interfaces:       [loopback_name]
	include_loopback: true
	include_ipv6:     false
}

fn test_a_client_discovers_a_server_and_exchanges_messages() {
	mut host := listen(':${test_port}',
		network_id: test_network_id
		broadcast:  false
	)!
	defer {
		host.close()
	}
	host.set_server_data(ServerData{
		server_name:      'test'
		level_name:       'test level'
		max_player_count: 10
	})

	mut listener := nethernet.listen(mut host,
		allow_anonymous: true
		interfaces:      loopback_only
		logger:          transport_logger()
	)!
	defer {
		listener.close()
	}

	mut client := listen('',
		broadcast_address:  '127.0.0.1:${test_port}'
		broadcast_interval: 200 * time.millisecond
	)!
	defer {
		client.close()
	}

	// The client learns the server exists from its answer to a broadcast.
	network_id := await_server(mut client, 10 * time.second)!
	assert network_id == test_network_id

	mut accepted := chan &nethernet.Conn{cap: 1}
	spawn accept_one(mut listener, accepted)

	mut conn := nethernet.dial(network_id.str(), mut client,
		interfaces: loopback_only
		logger:     transport_logger()
	)!
	defer {
		conn.close()
	}

	// The server proves an identity even though the client presented none, and
	// the assertion is bound to this connection's DTLS fingerprints.
	assert conn.public_key() != none
	assert conn.identity_domain() == 'self'

	mut server_conn := &nethernet.Conn(unsafe { nil })
	select {
		server_conn = <-accepted {}
		10 * time.second {
			assert false, 'the listener did not accept the connection'
			return
		}
	}
	defer {
		server_conn.close()
	}

	conn.write('ping'.bytes())!
	assert server_conn.read_packet()! == 'ping'.bytes()

	server_conn.write('pong'.bytes())!
	assert conn.read_packet()! == 'pong'.bytes()
}

fn test_a_message_larger_than_one_segment_is_reassembled() {
	mut host := listen(':${test_port + 1}',
		network_id: test_network_id + 1
		broadcast:  false
	)!
	defer {
		host.close()
	}
	host.set_server_data(ServerData{
		server_name: 'test'
		level_name:  'test level'
	})

	mut listener := nethernet.listen(mut host,
		allow_anonymous: true
		interfaces:      loopback_only
		logger:          transport_logger()
	)!
	defer {
		listener.close()
	}

	mut client := listen('',
		broadcast_address:  '127.0.0.1:${test_port + 1}'
		broadcast_interval: 200 * time.millisecond
	)!
	defer {
		client.close()
	}

	network_id := await_server(mut client, 10 * time.second)!

	mut accepted := chan &nethernet.Conn{cap: 1}
	spawn accept_one(mut listener, accepted)

	mut conn := nethernet.dial(network_id.str(), mut client,
		interfaces: loopback_only
		logger:     transport_logger()
	)!
	defer {
		conn.close()
	}

	mut server_conn := &nethernet.Conn(unsafe { nil })
	select {
		server_conn = <-accepted {}
		10 * time.second {
			assert false, 'the listener did not accept the connection'
			return
		}
	}
	defer {
		server_conn.close()
	}

	// Two segments' worth, so the counter has to count down rather than being
	// zero from the start.
	payload := []u8{len: nethernet.max_message_size + 1024, init: u8(index % 251)}
	conn.write(payload)!
	assert server_conn.read_packet()! == payload
}

fn accept_one(mut listener nethernet.Listener, accepted chan &nethernet.Conn) {
	conn := listener.accept(15 * time.second) or { return }
	accepted <- conn
}

// await_server waits for a NetherNet server to answer a broadcast and returns
// its network ID.
fn await_server(mut client Listener, timeout time.Duration) !u64 {
	deadline := time.now().add(timeout)
	for time.now() < deadline {
		for network_id, _ in client.servers() {
			// Anything answering here is a NetherNet host: LAN discovery carries
			// nothing else.
			return network_id
		}
		time.sleep(100 * time.millisecond)
	}
	return error('no server answered within ${timeout.milliseconds()}ms')
}

// test_logger turns on the transport logs when NETHERNET_TEST_LOG is set, which
// is how a failure that only shows up under load is looked at.
fn transport_logger() logging.Logger {
	if os.getenv('NETHERNET_TEST_LOG') == '' {
		return logging.nop()
	}
	return logging.default('test', .debug)
}

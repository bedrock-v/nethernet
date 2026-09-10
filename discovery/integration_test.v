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

const observation_port = 17553

const observation_network_id = u64(998879)

fn test_a_connection_reports_its_channels_from_both_ends() {
	observations := chan nethernet.ChannelObservation{cap: 16}
	record := fn [observations] (o nethernet.ChannelObservation) {
		select {
			observations <- o {}
			else {}
		}
	}

	mut host := listen(':${observation_port}',
		network_id: observation_network_id
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
		observe_channel: record
	)!
	defer {
		listener.close()
	}

	mut client := listen('',
		broadcast_address:  '127.0.0.1:${observation_port}'
		broadcast_interval: 200 * time.millisecond
	)!
	defer {
		client.close()
	}

	network_id := await_server(mut client, 10 * time.second)!
	mut accepted := chan &nethernet.Conn{cap: 1}
	spawn accept_one(mut listener, accepted)

	mut conn := nethernet.dial(network_id.str(), mut client,
		interfaces:      loopback_only
		logger:          transport_logger()
		observe_channel: record
	)!
	defer {
		conn.close()
	}

	mut server_conn := &nethernet.Conn(unsafe { nil })
	select {
		c := <-accepted {
			server_conn = c
		}
		15 * time.second {
			assert false, 'the server never accepted the connection'
			return
		}
	}
	defer {
		server_conn.close()
	}

	mut seen := []nethernet.ChannelObservation{}
	for seen.len < 4 {
		select {
			o := <-observations {
				seen << o
			}
			10 * time.second {
				assert false, 'only ${seen.len} of 4 channel observations arrived'
				return
			}
		}
	}

	mut opened := []nethernet.ChannelObservation{}
	mut adopted := []nethernet.ChannelObservation{}
	for o in seen {
		if o.opened_locally {
			opened << o
		} else {
			adopted << o
		}
	}
	assert opened.len == 2, 'the client should have opened two channels'
	assert adopted.len == 2, 'the server should have adopted two channels'

	// Every channel is one of the two NetherNet ones, from both ends.
	for o in seen {
		assert o.reliability != none, 'channel "${o.label}" matched neither reliability'
		assert !o.negotiated, 'NetherNet channels are opened through DCEP, not negotiated'
		assert o.protocol == '', 'unexpected subprotocol "${o.protocol}"'
	}

	for o in adopted {
		reliability := o.reliability or { continue }
		assert o.label == reliability.label()
		match reliability {
			.reliable {
				assert o.ordered
				assert o.reliable
			}
			.unreliable {
				assert !o.reliable
			}
		}
		// The transports are up by the time the server adopts a channel, so it
		// runs on a stream the client and server both know.
		assert o.id != none, 'adopted channel "${o.label}" has no stream id'
	}
}

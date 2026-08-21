# nethernet

A pure V implementation of NetherNet, the WebRTC transport Minecraft: Bedrock
Edition uses for LAN, Xbox Live and Realms connections.

A NetherNet connection is a WebRTC peer connection with two data channels. What
makes it NetherNet rather than plain WebRTC is the negotiation around it:

- SDP offers and answers travel over an out-of-band **signalling channel**, one
  line at a time, rather than over HTTP.
- The description carries an `a=identity` attribute: a JWT naming a public key,
  plus a detached signature over the connection's DTLS fingerprints. That
  signature is what binds the identity to this particular connection.
- Game packets are split into segments of at most 262143 bytes, each prefixed
  with the number of segments still to come.

The `discovery` submodule implements the LAN half: the UDP broadcast on port
7551 that finds games, and the same socket carrying the signals that connect to
one.

## Installing

```
v install --git https://github.com/bedrock-v/webrtc-v
```

Then place this module where V can find it, e.g. symlink it into `~/.vmodules`:

```
ln -s "$PWD/nethernet" ~/.vmodules/nethernet
```

## Hosting a LAN game

```v
import nethernet
import nethernet.discovery
import time

mut signaling := discovery.listen(':${discovery.default_port}',
	network_id: 1122334455
	broadcast:  false
)!
signaling.set_server_data(discovery.ServerData{
	server_name:      'Vedrock'
	protocol:         800
	version:          '1.21.0'
	level_name:       'Vedrock level'
	max_player_count: 10
})

mut listener := nethernet.listen(mut signaling, allow_anonymous: true)!
for {
	mut conn := listener.accept(1 * time.hour)!
	spawn handle(mut conn)
}
```

A server binds port 7551 so clients broadcasting there find it, and does not
broadcast itself. `set_server_data` is what fills in the world card; a server
that already produces a RakNet pong response can pass it to `pong_data` instead.

The advertisement is version 7 of the structure, which is what current clients
read. There is no negotiation - a client speaks exactly one version - so the
`protocol` and `version` fields have to match the game the server actually
speaks, or the world shows up as incompatible.

## Joining one

```v
import nethernet
import nethernet.discovery
import time

mut signaling := discovery.listen('')!
time.sleep(3 * time.second) // let a broadcast go out and be answered

for network_id, server in signaling.servers() {
	println('${server.level_name} by ${server.server_name}')

	mut conn := nethernet.dial(network_id.str(), mut signaling)!
	conn.write('hello'.bytes())!
	println(conn.read_packet()!.bytestr())
	conn.close()
	break
}
```

A client binds an ephemeral port: 7551 is often already held by the game itself,
and a client only needs to receive replies.

Two runnable programs are in `examples/`:

```sh
v run examples/lan_server            # binds 7551, advertises a world
v run examples/lan_client            # finds it and sends a message
```

The game holds port 7551 while it is running, so pass the server an address to
bind somewhere else - `v run examples/lan_server :27551` - and point the client
at it with `v run examples/lan_client 127.0.0.1:27551`. On a host with several
interfaces, set `NETHERNET_INTERFACE` to the one both ends should use;
`WEBRTC_LOG_LEVEL=debug` shows what the transports are doing.

## Identity

Both ends may present an identity, and each decides whether to require one.

A **server** signs its own token, so verifying it proves the server holds the key
it names and nothing more - trust on first use. `nethernet.listen` generates a
key at startup if none is configured, which means a client that remembers keys
sees a different server after every restart. Pass a stored one to avoid that:

```v
identity := nethernet.generate_server_identity(private_key, 'self')!
mut listener := nethernet.listen(mut signaling, identity: identity)!
```

A **client**'s token is issued by Minecraft's authorization service and signed
with RS256, which this module does not verify. What it does check is that the
assertion in the offer was made with the key the token claims, binding that key
to this connection. A server must still verify the Login packet's token at the
protocol layer and confirm it names the same key - otherwise a client may present
any token it likes over a connection it legitimately holds the key for.

`allow_anonymous` on the listener and `allow_identityless_server` on the dialer
turn the respective requirement off. Both are downgrades: without an assertion
there is nothing tying the description to a known peer, so whoever intercepted
the offer could have answered it. An offline LAN server needs `allow_anonymous`,
because an offline client presents no identity.

`conn.public_key()` returns the key the peer proved, or none if it presented
none.

## Connections

`Conn` carries whole messages rather than a byte stream, which is what the game's
decoder wants:

- `read_packet()` returns the next whole message from the reliable channel.
- `write(data)` sends one, splitting it into segments when it does not fit.
- `send(data, .unreliable)` and `receive(.unreliable, timeout)` use the other
  channel. Vanilla opens it but appears never to use it, and a dropped segment
  would leave a multi-segment message unfinishable, so a message sent there must
  fit in one segment.
- `read(mut b)` is a byte-oriented read for callers that want one.

`disable_encryption()` reports true: DTLS already encrypts every byte, so the
game protocol should not add a second layer. That does mean the protocol layer
loses the replay protection its own encryption gives it - see the note on
identity above.

## Non-trickle ICE

Dedicated servers with `nethernet-disable-trickle-ice` set, and Realms, cannot
carry candidates after the initial description. Set `disable_trickle_ice` on
either config and every local candidate is gathered before the offer or answer is
sent, and embedded in it. It is slower, because nothing can be sent until
gathering finishes.

A signalling implementation that knows it cannot trickle should report so from
`disable_trickle_ice()`, which overrides the configured value.

## Multi-homed hosts

Every gathered address is disclosed to the peer, and on a host with several
interfaces - a docker bridge alongside the real network - the two ends can settle
on candidate pairs that cannot reach each other. `interfaces` on either config
narrows gathering:

```v
mut conn := nethernet.dial(network_id, mut signaling,
	interfaces: ice.InterfaceOptions{
		interfaces: ['eth0']
	}
)!
```

## Signalling elsewhere

`discovery.Listener` is one implementation of the `Signaling` interface. An Xbox
Live or Realms connection uses a WebSocket instead; implementing the same
interface is all that is needed to use `dial` and `listen` over it:

```v
pub interface Signaling {
	network_id() string
	disable_trickle_ice() bool
mut:
	signal(sig Signal) !
	notify(n Notifier) int
	stop_notify(id int)
	credentials() !Credentials
	pong_data(data []u8)
	is_closed() bool
}
```

`credentials()` is where a WebSocket-based channel returns the STUN and TURN
servers the service hands out. A LAN channel returns an empty set: every peer is
directly reachable.

## Testing

```
v test .
v test discovery
```

`discovery/integration_test.v` runs both ends in one process over loopback: LAN
discovery, the offer and answer, the transports coming up, and a message in each
direction including one large enough to be segmented.

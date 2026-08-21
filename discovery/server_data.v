module discovery

// GameType is the game mode a world hands new players.
pub const game_type_survival = i32(0)

pub const game_type_creative = i32(1)

pub const game_type_adventure = i32(2)

// connection_type_lan is the connection type vanilla advertises when the
// signalling channel is the local network.
pub const connection_type_lan = i32(4)

// server_data_version is the version of the structure below. A client that
// reads a different one ignores the response.
//
// Version 7 dropped the transport layer field and added the host's protocol and
// game version, and moved the player counts to varints. There is no negotiation
// here - a client speaks exactly one version - so a server advertising the wrong
// one is simply not seen.
pub const server_data_version = u8(7)

// ServerData describes a world in the LAN game list.
pub struct ServerData {
pub mut:
	// server_name is shown under the level name in the world card. It is usually
	// the host player's name.
	server_name string
	// protocol is the Bedrock protocol version the host speaks. A client whose
	// own protocol differs marks the world as incompatible in the list.
	protocol i32
	// version is the host's game version, as displayed to a player.
	version string
	// level_name is the world's name, shown at the top of the card.
	level_name string
	// player_count and max_player_count fill in the card's player line.
	player_count     i32
	max_player_count i32
	// game_type is the mode a joining player is put in. It is fixed for the
	// lifetime of the world.
	game_type i32
	// editor_world marks a world created as an Editor project. Only a client in
	// Editor Mode shows it.
	editor_world bool
	// hardcore marks a hardcore world. A hardcore world is normally survival
	// too, so game_type should say so.
	hardcore bool
	// accepts_online_auth and accepts_self_signed_auth say which kinds of player
	// the server will let in: Xbox Live authenticated, self-signed, or both.
	accepts_online_auth      bool = true
	accepts_self_signed_auth bool = true
	// nonce is a hex string the host generates. A client connecting must echo it
	// back in the Nonce field of its Login packet, which ties the login to this
	// advertisement.
	nonce string
	// connection_type is 4 when the local network is the signalling channel.
	connection_type i32 = connection_type_lan
}

// encode renders the data for a ResponsePacket.
pub fn (d &ServerData) encode() []u8 {
	mut w := Writer{}
	w.u8(server_data_version)
	w.string(d.server_name)
	w.varint32(d.protocol)
	w.string(d.version)
	w.string(d.level_name)
	w.varint32(d.player_count)
	w.varint32(d.max_player_count)
	w.varint32(d.game_type)
	w.bool(d.editor_world)
	w.bool(d.hardcore)
	w.bool(d.accepts_online_auth)
	w.bool(d.accepts_self_signed_auth)
	w.string(d.nonce)
	w.varint32(d.connection_type)
	return w.data
}

// ServerData.decode reads the data out of a ResponsePacket.
pub fn ServerData.decode(data []u8) !ServerData {
	mut r := Reader{
		data: data
	}
	version := r.u8()!
	if version != server_data_version {
		return error('discovery: server data version ${version}, expected ${server_data_version}')
	}

	server := ServerData{
		server_name:              r.string()!
		protocol:                 r.varint32()!
		version:                  r.string()!
		level_name:               r.string()!
		player_count:             r.varint32()!
		max_player_count:         r.varint32()!
		game_type:                r.varint32()!
		editor_world:             r.bool()!
		hardcore:                 r.bool()!
		accepts_online_auth:      r.bool()!
		accepts_self_signed_auth: r.bool()!
		nonce:                    r.string()!
		connection_type:          r.varint32()!
	}
	if r.remaining() != 0 {
		return error('discovery: ${r.remaining()} bytes left after the server data')
	}
	return server
}

// ServerData.from_pong builds the data from a RakNet pong response, which is
// the format a Bedrock server layer already produces.
//
// The pong is a semicolon-separated list; the fields taken here are the ones
// the world card shows.
pub fn ServerData.from_pong(pong []u8) !ServerData {
	fields := pong.bytestr().split(';')
	if fields.len < 9 {
		return error('discovery: pong data has ${fields.len} fields, expected at least 9')
	}
	return ServerData{
		server_name:      fields[1]
		protocol:         i32(fields[2].int())
		version:          fields[3]
		level_name:       fields[7]
		player_count:     i32(fields[4].int())
		max_player_count: i32(fields[5].int())
		game_type:        parse_pong_game_type(fields[8])
	}
}

fn parse_pong_game_type(value string) i32 {
	return match value.trim_space().to_lower() {
		'creative' { game_type_creative }
		'adventure' { game_type_adventure }
		else { game_type_survival }
	}
}

module endpoint

import x.json2

// GameType is the mode a world hands a joining player.
pub const game_type_survival = 0

pub const game_type_creative = 1

pub const game_type_adventure = 2

// Status is what a server answers a join ping with. It is the address join
// equivalent of the LAN game card: the client shows it in the server list
// before anything is negotiated.
pub struct Status {
pub mut:
	// server_name is shown as the MOTD.
	server_name string @[json: 'name']
	// protocol is the Bedrock protocol version the server speaks.
	protocol int @[json: 'protocol']
	// version is the game version, as displayed to a player.
	version string @[json: 'version']
	// level_name is the world's name. The server card never shows it.
	level_name string @[json: 'level']
	player_count     int @[json: 'players']
	max_player_count int @[json: 'maxPlayers']
	// game_type is the mode a joining player is put in.
	game_type int @[json: 'gameType']
}

// encode renders the status as the JSON body of a join ping response.
pub fn (s Status) encode() string {
	return json2.encode(s)
}

// Status.from_pong reads a RakNet pong response, which is the format a Bedrock
// server layer already produces for its MOTD.
pub fn Status.from_pong(data []u8) !Status {
	fields := data.bytestr().split(';')
	if fields.len < 9 {
		return error('endpoint: pong data has ${fields.len} fields, expected at least 9')
	}
	return Status{
		server_name:      fields[1]
		protocol:         fields[2].int()
		version:          fields[3]
		level_name:       fields[7]
		player_count:     fields[4].int()
		max_player_count: fields[5].int()
		game_type:        parse_pong_game_type(fields[8])
	}
}

fn parse_pong_game_type(value string) int {
	return match value.trim_space().to_lower() {
		'creative' { game_type_creative }
		'adventure' { game_type_adventure }
		else { game_type_survival }
	}
}

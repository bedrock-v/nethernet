module endpoint

// The client reads the ping body by field name, so a renamed field is a server
// it cannot describe.
fn test_status_encodes_the_names_the_client_reads() {
	body := Status{
		server_name:      'Vedrock'
		protocol:         2192
		version:          '1.26.50'
		level_name:       'world'
		player_count:     3
		max_player_count: 20
		game_type:        game_type_creative
	}.encode()

	assert body.contains('"name":"Vedrock"')
	assert body.contains('"protocol":2192')
	assert body.contains('"version":"1.26.50"')
	assert body.contains('"level":"world"')
	assert body.contains('"players":3')
	assert body.contains('"maxPlayers":20')
	assert body.contains('"gameType":1')
}

fn test_status_from_pong() {
	pong := 'MCPE;Vedrock;2192;1.26.50;3;20;12345;world;Creative;1;19132;19132;0;'
	status := Status.from_pong(pong.bytes())!
	assert status.server_name == 'Vedrock'
	assert status.protocol == 2192
	assert status.version == '1.26.50'
	assert status.player_count == 3
	assert status.max_player_count == 20
	assert status.level_name == 'world'
	assert status.game_type == game_type_creative
}

fn test_status_from_pong_rejects_a_short_response() {
	if _ := Status.from_pong('MCPE;Vedrock'.bytes()) {
		assert false, 'a pong with too few fields was accepted'
	}
}

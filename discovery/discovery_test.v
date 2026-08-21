module discovery

fn test_request_packet_round_trip() {
	encoded := marshal(RequestPacket{}, 42)
	pk, sender_id := unmarshal(encoded)!

	assert sender_id == 42
	assert pk is RequestPacket
}

fn test_response_packet_carries_server_data() {
	data := ServerData{
		server_name:      'Eris'
		protocol:         800
		version:          '1.21.0'
		level_name:       'Bedrock level'
		game_type:        game_type_creative
		player_count:     3
		max_player_count: 10
		nonce:            'a1b2c3'
	}
	encoded := marshal(ResponsePacket{
		application_data: data.encode()
	}, 7)

	pk, sender_id := unmarshal(encoded)!
	assert sender_id == 7
	if pk is ResponsePacket {
		decoded := ServerData.decode(pk.application_data)!
		assert decoded.server_name == 'Eris'
		assert decoded.protocol == 800
		assert decoded.version == '1.21.0'
		assert decoded.level_name == 'Bedrock level'
		assert decoded.game_type == game_type_creative
		assert decoded.player_count == 3
		assert decoded.max_player_count == 10
		assert decoded.nonce == 'a1b2c3'
		assert decoded.connection_type == connection_type_lan
	} else {
		assert false, 'expected a ResponsePacket'
	}
}

fn test_message_packet_carries_a_signal() {
	encoded := marshal(MessagePacket{
		recipient_id: 1234
		data:         'CONNECTREQUEST 99 v=0'
	}, 5)

	pk, _ := unmarshal(encoded)!
	if pk is MessagePacket {
		assert pk.recipient_id == 1234
		assert pk.data == 'CONNECTREQUEST 99 v=0'
	} else {
		assert false, 'expected a MessagePacket'
	}
}

fn test_tampered_packet_is_rejected() {
	mut encoded := marshal(RequestPacket{}, 1)
	// Flip a bit in the ciphertext; the HMAC covers the plaintext, so the
	// decrypted result no longer matches it.
	encoded[encoded.len - 1] ^= 0xff

	if _, _ := unmarshal(encoded) {
		assert false, 'a tampered packet was accepted'
	}
}

fn test_padding_round_trip() {
	for length in [0, 1, 15, 16, 17, 64] {
		src := []u8{len: length, init: u8(index)}
		assert unpad(pad(src))! == src
	}
}

fn test_varint_round_trip() {
	for value in [i32(0), 1, -1, 63, -64, 2147483647, -2147483648] {
		mut w := Writer{}
		w.varint32(value)
		mut r := Reader{
			data: w.data
		}
		assert r.varint32()! == value
	}
}

fn test_server_data_from_pong() {
	pong := 'MCPE;Dedicated Server;800;1.21.0;2;10;13253860892328930865;Bedrock level;Survival;1;19132;19133;'
	data := ServerData.from_pong(pong.bytes())!

	assert data.server_name == 'Dedicated Server'
	assert data.protocol == 800
	assert data.version == '1.21.0'
	assert data.level_name == 'Bedrock level'
	assert data.game_type == game_type_survival
	assert data.player_count == 2
	assert data.max_player_count == 10
}

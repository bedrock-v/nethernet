module endpoint

import net.http
import nethernet

// AnsweringNotifier stands in for a Listener: it answers every offer it is
// given, from another thread, the way a real negotiation does.
struct AnsweringNotifier {
mut:
	handler &EndpointHandler
	answer  string
}

fn (mut n AnsweringNotifier) notify_signal(sig nethernet.Signal) bool {
	if sig.typ != nethernet.signal_type_offer {
		return false
	}
	answer := nethernet.Signal{
		typ:           nethernet.signal_type_answer
		connection_id: sig.connection_id
		data:          n.answer
		network_id:    sig.network_id
	}
	mut handler := n.handler
	spawn fn (mut h EndpointHandler, sig nethernet.Signal) {
		h.signal(sig) or {}
	}(mut handler, answer)
	return true
}

fn test_ping_answers_with_the_status() {
	mut h := listen(address: '127.0.0.1:0')!
	defer {
		h.close()
	}
	addr := h.server.addr

	empty := http.get('http://${addr}/v1/join')!
	assert empty.status() == .ok
	assert empty.body == ''

	h.set_status(Status{
		server_name:      'Vedrock'
		protocol:         2192
		max_player_count: 20
	})
	described := http.get('http://${addr}/v1/join')!
	assert described.status() == .ok
	assert described.body.contains('"name":"Vedrock"')
	assert described.body.contains('"protocol":2192')
}

fn test_offer_is_answered_with_the_listeners_answer() {
	mut h := listen(address: '127.0.0.1:0')!
	defer {
		h.close()
	}
	mut notifier := &AnsweringNotifier{
		handler: h
		answer:  'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n'
	}
	h.notify(notifier)

	answered := http.post('http://${h.server.addr}/v1/join/123', 'v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n')!
	assert answered.status() == .ok, 'answered ${answered.status_code}: ${answered.body}'
	assert answered.body == notifier.answer
}

fn test_offer_without_a_listener_is_refused() {
	mut h := listen(address: '127.0.0.1:0')!
	defer {
		h.close()
	}

	refused := http.post('http://${h.server.addr}/v1/join/123', 'v=0\r\n')!
	assert refused.status() == .internal_server_error
}

fn test_a_malformed_offer_is_rejected() {
	mut h := listen(address: '127.0.0.1:0')!
	defer {
		h.close()
	}

	empty := http.post('http://${h.server.addr}/v1/join/123', '')!
	assert empty.status() == .bad_request

	unnumbered := http.post('http://${h.server.addr}/v1/join/world', 'v=0\r\n')!
	assert unnumbered.status() == .bad_request
}

// A candidate has nowhere to go once the answer has been written, so the
// listener has to be told rather than left waiting.
fn test_a_candidate_cannot_be_signalled() {
	mut h := listen(address: '127.0.0.1:0')!
	defer {
		h.close()
	}
	if _ := h.signal(nethernet.Signal{
		typ:           nethernet.signal_type_candidate
		connection_id: 1
		network_id:    '123'
	})
	{
		assert false, 'a candidate was accepted'
	}
}

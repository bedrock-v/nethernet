module nethernet

// Where an address sits, which decides whether it is worth announcing to a peer
// or worth trying to reach one at.
//
// The distinctions that matter here are the ones no standard library predicate
// draws: carrier grade NAT, which a tethered or overlay peer sits behind, and
// the IPv6 unique local range. Both are private rather than useless, and
// treating them as either public or unusable gets connectivity wrong.
pub enum AddressScope {
	// public_ is globally reachable unicast.
	public_
	// private_ is reachable from the same network or overlay: RFC 1918, carrier
	// grade NAT, unique local.
	private_
	// loopback is this host only.
	loopback
	// unusable is special purpose, documentation, or otherwise no use to a peer.
	unusable
}

// address_scope classifies an IP literal. A name, or anything that is not an
// address at all, is unusable: resolving here would block and could only answer
// for this host.
pub fn address_scope(address string) AddressScope {
	if octets := parse_ipv4(address) {
		return ipv4_scope(octets)
	}
	if words := parse_ipv6(address) {
		return ipv6_scope(words)
	}
	return .unusable
}

// is_routable reports whether a peer on another network could reach this
// address.
pub fn is_routable(address string) bool {
	return address_scope(address) == .public_
}

fn ipv4_scope(o [4]u8) AddressScope {
	a, b, c, d := o[0], o[1], o[2], o[3]
	if a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168)
		|| (a == 100 && b >= 64 && b <= 127) {
		return .private_
	}
	if a == 127 {
		return .loopback
	}
	// 192.0.0.9 and .10 are the PCP and TURN anycast addresses, which a peer can
	// reach; the rest of 192.0.0.0/24 it cannot.
	if a == 0 || a >= 224 || (a == 169 && b == 254) || (a == 203 && b == 0 && c == 113)
		|| (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
		|| (a == 192 && ((b == 88 && c == 99) || (b == 0 && (c == 2 || (c == 0 && d != 9 && d != 10))))) {
		return .unusable
	}
	return .public_
}

fn ipv6_scope(w [8]u16) AddressScope {
	if w[0] & 0xfe00 == 0xfc00 {
		return .private_
	}
	if w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 0 && w[4] == 0 && w[5] == 0 && w[6] == 0
		&& w[7] == 1 {
		return .loopback
	}
	// An IPv4-mapped address is the IPv4 one it wraps.
	if w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 0 && w[4] == 0 && w[5] == 0xffff {
		return ipv4_scope([u8(w[6] >> 8), u8(w[6] & 0xff), u8(w[7] >> 8), u8(w[7] & 0xff)]!)
	}
	// Global unicast is 2000::/3 alone, less 6to4, the protocol block and the two
	// documentation ranges.
	if w[0] & 0xe000 != 0x2000 || w[0] == 0x2002 || (w[0] == 0x2001 && (w[1] < 0x200 || w[1] == 0xdb8))
		|| (w[0] == 0x3fff && w[1] < 0x1000) {
		return .unusable
	}
	return .public_
}

// parse_ipv4 reads a dotted quad. Anything else, including a quad with leading
// zeros, is refused: an octet written as "010" is read as octal by some
// resolvers and as decimal by others, and the two disagree about what address
// it is.
fn parse_ipv4(address string) ?[4]u8 {
	fields := address.split('.')
	if fields.len != 4 {
		return none
	}
	mut out := [4]u8{}
	for index, field in fields {
		if field.len == 0 || field.len > 3 || (field.len > 1 && field[0] == `0`) {
			return none
		}
		mut value := 0
		for c in field {
			if c < `0` || c > `9` {
				return none
			}
			value = value * 10 + int(c - `0`)
		}
		if value > 255 {
			return none
		}
		out[index] = u8(value)
	}
	return out
}

// parse_ipv6 reads a textual IPv6 address, including the "::" run and a
// trailing dotted quad. A zone identifier is dropped: it names an interface on
// the machine that wrote it and means nothing here.
fn parse_ipv6(address string) ?[8]u16 {
	mut text := address
	if index := text.index('%') {
		text = text[..index]
	}
	if !text.contains(':') {
		return none
	}

	// A trailing dotted quad stands for the last two words.
	mut tail := []u16{}
	if last := text.last_index(':') {
		candidate := text[last + 1..].clone()
		if candidate.contains('.') {
			octets := parse_ipv4(candidate)?
			tail = [u16(octets[0]) << 8 | octets[1], u16(octets[2]) << 8 | octets[3]]
			text = text[..last + 1] + '0'
		}
	}

	head_text, gap_text := split_ipv6_gap(text)?
	mut head := parse_ipv6_words(head_text)?
	mut gap := parse_ipv6_words(gap_text)?
	if tail.len != 0 {
		// The placeholder word stood in for the quad, which is two words wide.
		if gap_text != '' {
			gap = gap[..gap.len - 1]
			gap << tail
		} else {
			head = head[..head.len - 1]
			head << tail
		}
	}

	if head.len + gap.len > 8 {
		return none
	}
	if gap_text == '' && !text.contains('::') && head.len != 8 {
		return none
	}

	mut out := [8]u16{}
	for index, word in head {
		out[index] = word
	}
	for index, word in gap {
		out[8 - gap.len + index] = word
	}
	return out
}

// split_ipv6_gap separates the words before and after the "::" run. Without one
// the whole address is the head.
fn split_ipv6_gap(text string) ?(string, string) {
	if !text.contains('::') {
		return text, ''
	}
	parts := text.split('::')
	if parts.len != 2 {
		return none
	}
	return parts[0], parts[1]
}

fn parse_ipv6_words(text string) ?[]u16 {
	if text == '' {
		return []u16{}
	}
	mut out := []u16{}
	for field in text.split(':') {
		if field.len == 0 || field.len > 4 {
			return none
		}
		mut value := u32(0)
		for c in field {
			digit := match true {
				c >= `0` && c <= `9` { u32(c - `0`) }
				c >= `a` && c <= `f` { u32(c - `a` + 10) }
				c >= `A` && c <= `F` { u32(c - `A` + 10) }
				else { return none }
			}
			value = value << 4 | digit
		}
		out << u16(value)
	}
	return out
}

// split_host_port separates an "ip:port" or "[ipv6]:port" pair. The port is
// returned as it was written, so a caller that only wants the host can ignore
// it without parsing a number it does not need.
fn split_host_port(address string) ?(string, string) {
	if address == '' {
		return none
	}
	if address.starts_with('[') {
		end := address.index(']')?
		if end + 1 >= address.len || address[end + 1] != `:` {
			return none
		}
		return address[1..end], address[end + 2..]
	}
	index := address.last_index(':')?
	if address[..index].contains(':') {
		// A bare IPv6 address with no port at all.
		return none
	}
	return address[..index], address[index + 1..]
}

// address_key is a canonical form of an IP literal, so the same address written
// two ways compares equal. Anything that is not an IP literal, such as an mDNS
// ".local" candidate, is compared as it stands rather than resolved.
fn address_key(address string) string {
	if octets := parse_ipv4(address) {
		return '4:${octets[0]}.${octets[1]}.${octets[2]}.${octets[3]}'
	}
	if words := parse_ipv6(address) {
		mut out := '6:'
		for index, word in words {
			if index > 0 {
				out += ':'
			}
			out += word.hex()
		}
		return out
	}
	return address.to_lower()
}

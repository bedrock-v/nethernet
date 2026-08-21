module discovery

// The encodings below are the ones Minecraft uses on this wire: fixed-width
// values little-endian, and the fields of ServerData as protobuf-style
// varints.

// Writer builds a packet.
struct Writer {
mut:
	data []u8
}

fn (mut w Writer) u8(value u8) {
	w.data << value
}

fn (mut w Writer) u16(value u16) {
	w.data << u8(value & 0xff)
	w.data << u8((value >> 8) & 0xff)
}

fn (mut w Writer) u32(value u32) {
	mut remaining := value
	for _ in 0 .. 4 {
		w.data << u8(remaining & 0xff)
		remaining >>= 8
	}
}

fn (mut w Writer) u64(value u64) {
	mut remaining := value
	for _ in 0 .. 8 {
		w.data << u8(remaining & 0xff)
		remaining >>= 8
	}
}

fn (mut w Writer) bool(value bool) {
	w.data << if value { u8(1) } else { u8(0) }
}

fn (mut w Writer) bytes(value []u8) {
	w.data << value
}

// varuint32 writes seven bits per byte, low bits first, with the top bit
// marking that another byte follows.
fn (mut w Writer) varuint32(value u32) {
	mut remaining := value
	for remaining >= 0x80 {
		w.data << u8(remaining) | 0x80
		remaining >>= 7
	}
	w.data << u8(remaining)
}

// varint32 zig-zag encodes the value first, so a small negative number stays
// short.
fn (mut w Writer) varint32(value i32) {
	mut zigzag := u32(value) << 1
	if value < 0 {
		zigzag = ~zigzag
	}
	w.varuint32(zigzag)
}

// string writes a length-prefixed string.
fn (mut w Writer) string(value string) {
	w.varuint32(u32(value.len))
	w.data << value.bytes()
}

// Reader takes a packet apart. Every read is bounds-checked: the bytes came off
// the network and the lengths in them are not to be trusted.
struct Reader {
	data []u8
mut:
	offset int
}

fn (r &Reader) remaining() int {
	return r.data.len - r.offset
}

fn (mut r Reader) u8() !u8 {
	if r.remaining() < 1 {
		return error('discovery: unexpected end of packet')
	}
	value := r.data[r.offset]
	r.offset++
	return value
}

fn (mut r Reader) u16() !u16 {
	if r.remaining() < 2 {
		return error('discovery: unexpected end of packet')
	}
	value := u16(r.data[r.offset]) | (u16(r.data[r.offset + 1]) << 8)
	r.offset += 2
	return value
}

fn (mut r Reader) u32() !u32 {
	if r.remaining() < 4 {
		return error('discovery: unexpected end of packet')
	}
	mut value := u32(0)
	for i := 3; i >= 0; i-- {
		value = (value << 8) | u32(r.data[r.offset + i])
	}
	r.offset += 4
	return value
}

fn (mut r Reader) u64() !u64 {
	if r.remaining() < 8 {
		return error('discovery: unexpected end of packet')
	}
	mut value := u64(0)
	for i := 7; i >= 0; i-- {
		value = (value << 8) | u64(r.data[r.offset + i])
	}
	r.offset += 8
	return value
}

fn (mut r Reader) bool() !bool {
	return r.u8()! != 0
}

fn (mut r Reader) take(count int) ![]u8 {
	if count < 0 || count > r.remaining() {
		return error('discovery: ${count} bytes requested, ${r.remaining()} remaining')
	}
	value := r.data[r.offset..r.offset + count]
	r.offset += count
	return value
}

fn (mut r Reader) varuint32() !u32 {
	mut value := u32(0)
	for shift := u32(0); shift < 35; shift += 7 {
		b := r.u8()!
		value |= u32(b & 0x7f) << shift
		if b & 0x80 == 0 {
			return value
		}
	}
	return error('discovery: varuint32 did not terminate within five bytes')
}

fn (mut r Reader) varint32() !i32 {
	zigzag := r.varuint32()!
	value := i32(zigzag >> 1)
	if zigzag & 1 != 0 {
		return ~value
	}
	return value
}

fn (mut r Reader) string() !string {
	length := r.varuint32()!
	return r.take(int(length))!.bytestr()
}

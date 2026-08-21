module nethernet

import crypto.ecdsa
import encoding.base64
import time
import x.json2

// Identity is the authenticated identity one end presents in its SDP.
//
// The token names a public key in its `cpk` claim; the detached signature over
// the DTLS fingerprints proves the sender holds the matching private key. That
// is what binds the identity to this particular peer connection - a token
// replayed onto another connection signs different fingerprints and fails.
pub struct Identity {
pub:
	// private_key signs the fingerprint assertion, and for a server identity
	// also signs the token itself. It must be the key named by `cpk`.
	private_key ecdsa.PrivateKey
	// token is the JWT for this identity. A client's is issued by Minecraft's
	// authorization service; a server's is self-signed.
	token string
	// domain names the issuer. It may be shown to a player on first join over an
	// insecure context. Bedrock Dedicated Server uses "self".
	domain string
}

// IdentityData is the `a=identity` attribute, base64-encoded in the SDP.
pub struct IdentityData {
pub mut:
	// fingerprints is the detached JWS over the DTLS fingerprints in the same
	// description.
	fingerprints string
	// token is the identity token the assertion is made under.
	token string
	// domain is the identity provider that issued the token: an authorization
	// service URL for a client, "self" or a hostname for a server.
	domain string
	// protocol is always "default" for NetherNet.
	protocol string = 'default'
}

// valid reports whether the assertion is well-formed. It says nothing about
// whether the signature checks out.
pub fn (d &IdentityData) valid() bool {
	return is_compact_jws(d.token) && is_compact_jws(d.fingerprints) && d.protocol == 'default'
		&& d.domain != ''
}

fn is_compact_jws(text string) bool {
	return text != '' && text.count('.') == 2
}

// TokenClaims are the claims a NetherNet identity token is read for. A client
// token carries more - a gamertag and an XUID among them - but nothing else is
// needed to bind the identity.
pub struct TokenClaims {
pub:
	// public_key is the `cpk` claim: the key the assertion must verify under.
	public_key ecdsa.PublicKey
	// expires_at and issued_at are the standard `exp` and `iat` claims, in
	// seconds since the Unix epoch. Zero means the claim was absent.
	expires_at i64
	issued_at  i64
}

// server_identity_lifetime matches what Bedrock Dedicated Server issues itself.
// The token is minted per connection, so a short life costs nothing and bounds
// how long a captured one is worth replaying.
const server_identity_lifetime = time.minute

// generate_server_identity self-signs a token for the given key.
//
// The domain may be surfaced to a player joining over an insecure context;
// Bedrock Dedicated Server passes "self". The key must be on P-384, because the
// assertion is signed with ES384.
pub fn generate_server_identity(private_key ecdsa.PrivateKey, domain string) !Identity {
	public_key := private_key.public_key()!
	encoded := base64.encode(encode_public_key(public_key)!)

	issued_at := time.now().unix()
	// Vanilla puts the public key in an `x5u` header as well as in `cpk`. It is
	// not required to verify anything, but matching the shape keeps the token
	// indistinguishable from one the game would issue.
	header := '{"alg":"ES384","x5u":"${encoded}"}'
	claims := '{"exp":${issued_at + i64(server_identity_lifetime / time.second)},"iat":${issued_at},"cpk":"${encoded}"}'
	return Identity{
		private_key: private_key
		token:       sign_compact(private_key, header, claims.bytes())!
		domain:      domain
	}
}

// sign builds the identity assertion for a local description.
//
// The signature covers the fingerprints exactly as they appear in the SDP being
// sent, so the assertion cannot be lifted onto a description with different
// DTLS certificates.
fn (i &Identity) sign(sdp_text string) !IdentityData {
	payload := fingerprints_payload(sdp_text)
	return IdentityData{
		fingerprints: detach_payload(sign_compact(i.private_key, '{"alg":"ES384"}', payload)!)
		token:        i.token
		domain:       i.domain
	}
}

// verify checks the fingerprint assertion against the description it arrived
// with, under the public key the token claimed.
fn (d &IdentityData) verify(sdp_text string, public_key ecdsa.PublicKey) ! {
	segments := d.fingerprints.split('.')
	if segments.len != 3 {
		return error('nethernet: fingerprint assertion has ${segments.len} segments, expected 3')
	}
	if segments[1] != '' {
		return error('nethernet: fingerprint assertion is not detached')
	}

	payload := fingerprints_payload(sdp_text)
	signing_input := '${segments[0]}.${base64url_encode(payload)}'
	signature := raw_signature_to_der(base64url_decode(segments[2])!)!

	verified := public_key.verify(signing_input.bytes(), signature) or {
		return error('nethernet: verify fingerprint assertion: ${err.msg()}')
	}
	if !verified {
		return error('nethernet: fingerprint assertion does not match the description')
	}
}

// claim_public_key reads the `cpk` claim, and when self_signed is set also
// checks that the token was signed by that key.
//
// A server token is self-signed, so the check is meaningful there. A client
// token is issued by Minecraft's authorization service and signed with RS256,
// which this package cannot verify: the caller is expected to check the Login
// packet's token at the protocol layer and confirm it names the same key.
pub fn claim_public_key(token string, self_signed bool) !ecdsa.PublicKey {
	segments := token.split('.')
	if segments.len != 3 {
		return error('nethernet: token has ${segments.len} segments, expected 3')
	}
	claims := parse_token_claims(base64url_decode(segments[1])!)!

	now := time.now().unix()
	if claims.expires_at != 0 && now > claims.expires_at {
		return error('nethernet: token expired at ${claims.expires_at}')
	}
	if claims.issued_at != 0 && claims.issued_at > now + i64(token_clock_skew / time.second) {
		return error('nethernet: token was issued at ${claims.issued_at}, in the future')
	}

	if self_signed {
		signature := raw_signature_to_der(base64url_decode(segments[2])!)!
		verified := claims.public_key.verify('${segments[0]}.${segments[1]}'.bytes(), signature) or {
			return error('nethernet: verify self-signed token: ${err.msg()}')
		}
		if !verified {
			return error('nethernet: token is not signed by the key it claims')
		}
	}
	return claims.public_key
}

// token_clock_skew is how far ahead of us a peer's clock may be before its
// token is treated as issued in the future.
const token_clock_skew = 60 * time.second

// parse_token_claims reads the claims this package needs out of a token
// payload.
fn parse_token_claims(payload []u8) !TokenClaims {
	decoded := json2.decode[json2.Any](payload.bytestr()) or {
		return error('nethernet: decode token claims: ${err.msg()}')
	}
	claims := decoded.as_map()

	cpk := claims['cpk'] or { return error('nethernet: token has no cpk claim') }
	return TokenClaims{
		public_key: parse_claim_public_key(cpk)!
		expires_at: if exp := claims['exp'] { exp.i64() } else { 0 }
		issued_at:  if iat := claims['iat'] { iat.i64() } else { 0 }
	}
}

// parse_claim_public_key reads a `cpk` claim, which is either a base64-encoded
// SubjectPublicKeyInfo or a JWK object. The game sends the former; the latter
// turns up in other implementations.
fn parse_claim_public_key(claim json2.Any) !ecdsa.PublicKey {
	if claim is map[string]json2.Any {
		return parse_jwk(claim)
	}
	encoded := claim.str()
	if encoded == '' {
		return error('nethernet: empty cpk claim')
	}
	der := base64.decode(encoded)
	if der.len == 0 {
		return error('nethernet: cpk claim is not valid base64')
	}
	return decode_public_key(der)
}

// parse_jwk reads an EC public key in JWK form, where the coordinates are
// base64url-encoded rather than wrapped in ASN.1.
fn parse_jwk(key map[string]json2.Any) !ecdsa.PublicKey {
	kty := if value := key['kty'] { value.str() } else { '' }
	if kty != 'EC' {
		return error('nethernet: cpk claim is a "${kty}" key, expected "EC"')
	}
	x_value := key['x'] or { return error('nethernet: JWK has no x coordinate') }
	y_value := key['y'] or { return error('nethernet: JWK has no y coordinate') }

	x := base64url_decode(x_value.str())!
	y := base64url_decode(y_value.str())!
	if x.len != y.len {
		return error('nethernet: JWK coordinates are ${x.len} and ${y.len} bytes')
	}

	// 0x04 marks the point as uncompressed, which is the only form used here.
	mut point := [u8(0x04)]
	point << x
	point << y
	return ecdsa.PublicKey.from_uncompressed_bytes(point, nid: jwk_curve(x.len)!)
}

fn jwk_curve(coordinate_len int) !ecdsa.Nid {
	return match coordinate_len {
		32 { ecdsa.Nid.prime256v1 }
		48 { ecdsa.Nid.secp384r1 }
		66 { ecdsa.Nid.secp521r1 }
		else { error('nethernet: JWK coordinates of ${coordinate_len} bytes name no supported curve') }
	}
}

// sign_compact produces a compact JWS over the payload.
fn sign_compact(private_key ecdsa.PrivateKey, header string, payload []u8) !string {
	signing_input := '${base64url_encode(header.bytes())}.${base64url_encode(payload)}'

	der := private_key.sign(signing_input.bytes())!
	size := curve_key_size(private_key.public_key()!.uncompressed_bytes()!.len)!
	return '${signing_input}.${base64url_encode(der_signature_to_raw(der, size)!)}'
}

// detach_payload removes the payload from a compact JWS, leaving the
// `header..signature` form the identity assertion carries. The payload is
// reconstructed from the description, so sending it would be redundant - and
// would let the two disagree.
fn detach_payload(jws string) string {
	segments := jws.split('.')
	if segments.len != 3 {
		return jws
	}
	return '${segments[0]}..${segments[2]}'
}

// fingerprints_payload builds the JSON the assertion signs, from the
// fingerprint lines of a description.
//
// It reads the SDP text rather than a parsed structure because the signature
// covers the exact digest strings that were sent; re-rendering them risks
// changing the case or the separators and breaking the signature.
fn fingerprints_payload(sdp_text string) []u8 {
	mut out := '{"fingerprint":['
	mut count := 0
	for line in sdp_text.split_into_lines() {
		trimmed := line.trim_space()
		if !trimmed.starts_with('a=fingerprint:') {
			continue
		}
		fields := trimmed['a=fingerprint:'.len..].split(' ').filter(it != '')
		if fields.len != 2 {
			continue
		}
		if count > 0 {
			out += ','
		}
		out += '{"algorithm":"${fields[0]}","digest":"${fields[1]}"}'
		count++
	}
	return '${out}]}'.bytes()
}

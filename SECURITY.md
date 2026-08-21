# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's [private vulnerability
reporting](https://github.com/bedrock-v/nethernet-v/security/advisories/new). If
you cannot use that, email **security@vedrock.dev** with `nethernet-v` in the
subject.

Please include:

- The affected version or commit.
- What an attacker can do, and what position they need to be in to do it (on the
  same local network, on-path, a peer we have signalled with, an arbitrary
  host).
- A reproduction: a signal, a packet, an SDP, a test case, or a description
  precise enough to rebuild one.
- Anything you know about the impact - a panic, an out-of-bounds read, an
  unbounded allocation, a bypassed identity check, a connection taken over.

You do not need a working exploit. A crashing input is a complete report.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 3 working days |
| Initial assessment, with a severity | 10 working days |
| Fix for a high or critical issue | 30 days from assessment |
| Fix for a low or medium issue | the next scheduled release |

If we cannot meet a target we will say so, and why, before it passes.

We will credit you in the advisory and the changelog unless you ask us not to.
We do not currently offer a bounty.

### Coordinated disclosure

We ask for 90 days from the acknowledgement before public disclosure, or until a
fix is released, whichever comes first. If a fix will take longer we will explain
why and agree a date with you. If an issue is being exploited in the wild, tell
us and we will move immediately.

## Supported versions

This project is pre-1.0. Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| latest release | ✅ |
| anything older | ❌ |

## Scope

This module parses two kinds of attacker-controlled input before anything has
been authenticated: discovery packets broadcast on the local network, and the
signals - SDP descriptions, ICE candidates, identity assertions - that negotiate
a connection. The following are in scope and we want to hear about them:

- **Memory safety** - an out-of-bounds read or write, or a panic reachable from a
  discovery packet, a signal, an SDP or a data channel message. Every decoder is
  expected to reject malformed input as an error; a panic is a bug even if V
  catches it.
- **Resource exhaustion** - an input that causes unbounded allocation, unbounded
  CPU, or unbounded growth of an internal buffer. The message reassembler has a
  documented ceiling of 256 segments of 262143 bytes; a way past it, or any other
  buffer a peer can grow without limit, is a vulnerability.
- **Identity bypass** - anything that makes a peer's identity assertion pass when
  it should not. Specifically: an assertion whose detached signature does not
  cover the DTLS fingerprints of the description it arrived in; an assertion
  accepted under a public key other than the one its token claims; an expired
  token accepted; a self-signed server token accepted that is not signed by the
  key in its own `cpk` claim; or a connection reporting a `public_key()` the peer
  did not prove it holds.
- **Assertion replay** - an identity assertion captured from one connection and
  accepted on another. The signature covers the fingerprints of the description
  it belongs to precisely so this cannot work.
- **Connection confusion** - a signal from one network or connection ID applied
  to a different connection: an ICE candidate injected into somebody else's peer
  connection, an answer accepted for a connection that did not offer it, or a
  discovery message routed to the wrong network.
- **Cryptographic misuse** - a non-constant-time comparison of a secret or a
  message authentication code, a signature verified against a reconstructed
  payload that differs from the one signed, or a key parsed in a way that accepts
  a value the sender does not hold the private half of.

### Out of scope

- **The discovery packet encryption.** The key is derived from a constant every
  Bedrock client knows, so the AES-ECB layer and its HMAC are an integrity check
  and a filter against unrelated traffic on the port - not authentication.
  Anybody on the local network can produce a valid discovery packet. That is what
  the game does, and interoperating means doing the same; see the note under
  known limitations.
- Vulnerabilities in [webrtc-v](https://github.com/bedrock-v/webrtc-v) itself -
  ICE, DTLS, SCTP, the data channels. Report those there; tell us too if this
  module is affected and we will work around it.
- Vulnerabilities in the V compiler or standard library. Report those to
  [vlang/v](https://github.com/vlang/v/issues).
- Denial of service that requires the attacker to already be on the path and able
  to drop packets. UDP offers no protection against that and neither can we.
- The fact that ICE discloses local IP addresses to the peer. That is what ICE
  is; use the `interfaces` filter to control which addresses are gathered.
- Attacks that require the application to disable a check the module performs -
  `allow_anonymous` on a listener, `allow_identityless_server` on a dialer. Both
  are documented downgrades.
- Anything in the `inspirations/` directory, which is reference material and not
  part of the module.

## Security properties this module aims to provide

Stated plainly so that a deviation is recognisable as a bug:

1. No input from the network causes a panic, an out-of-bounds access, or an
   allocation not bounded by a documented limit. A discovery packet's length
   fields, an SDP's attributes and a data channel message's segment counter are
   all treated as hostile.
2. A message is reassembled only from segments whose counters run consecutively
   down to zero. A segment out of sequence ends the connection rather than
   splicing unrelated bytes together, and a message spans at most 256 segments.
3. An identity assertion is verified against the DTLS fingerprints of the
   description it arrived in, under the public key that description's token
   claims. An assertion lifted onto another connection signs different
   fingerprints and fails.
4. A self-signed server token is accepted only when it is signed by the key in
   its own `cpk` claim, and only while it is inside its validity window.
5. A connection is refused when the peer presents no identity assertion, unless
   the application has explicitly allowed anonymous peers.
6. A signal reaches a connection only when both its connection ID and its network
   ID match that connection. A candidate or an error signalled for one connection
   cannot touch another.
7. A discovery packet's HMAC is checked before any part of its payload is
   decoded, and the comparison is constant time.
8. `public_key()` returns a key only when the peer proved possession of it on
   this connection.

## Known limitations

These are design limits, not bugs, and are documented so nobody mistakes one for
a guarantee:

- **The module is pre-1.0 and has not been independently audited.** It sits on
  webrtc-v, which is also pre-1.0 and unaudited. Do not deploy it where a
  compromise would be serious without reviewing both yourself.
- **Client identity tokens are not cryptographically verified.** A client's token
  is issued by Minecraft's authorization service and signed with RS256, and this
  module does not fetch that service's keys. What is verified is the binding
  between the token's `cpk` claim and this connection. A server must also verify
  the Login packet's token at the protocol layer and confirm it names the same
  key - otherwise a client may present any token it likes over a connection it
  legitimately holds the key for.
- **Server identity is trust on first use.** A server token is self-signed, so
  verifying it proves the server holds the key it names and nothing else. A
  client that cares which server it is talking to must compare `public_key()`
  against one it already knows. `nethernet.listen` generates a key at startup
  when none is configured, which means every restart looks like a different
  server; pass a stored identity to avoid that.
- **Discovery is unauthenticated.** Any host on the local network can advertise a
  world, answer a broadcast, or send a signal that appears to come from any
  network ID it likes. The peer connection underneath is still authenticated by
  DTLS and the identity assertion, so a forged signal cannot produce a connection
  to a server the client did not verify - but it can deny service and it can
  populate the game list with worlds that do not exist.
- **`Conn.disable_encryption()` reports true.** DTLS already encrypts every byte,
  so the game protocol should not add a second layer. That does mean the protocol
  layer loses the replay protection its own encryption gives it: a server should
  confirm the player really joined the Xbox Live session rather than trusting the
  Login packet alone.
- **The discovery cipher is AES-ECB with a constant key.** ECB leaks which blocks
  of a message repeat, and the key is public. Both are properties of the format
  the game defined; nothing that travels over it is treated as secret or as
  authenticated.
- **A `cpk` claim is accepted on P-256, P-384 or P-521.** The assertion is signed
  with ES384, and verification uses the hash the key's curve implies, so a peer
  presenting a key on another curve fails verification rather than being rejected
  at parse time. Vanilla uses P-384.

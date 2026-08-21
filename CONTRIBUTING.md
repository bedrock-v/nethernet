# Contributing

Thanks for considering it. This document covers what you need to know to get a
change merged.

## Getting set up

You need V 0.5.2 or newer, and [webrtc-v](https://github.com/bedrock-v/webrtc-v).

```sh
v install --git https://github.com/bedrock-v/webrtc-v

git clone https://github.com/bedrock-v/nethernet-v
cd nethernet-v
ln -s "$PWD" ~/.vmodules/nethernet   # so `import nethernet.discovery` resolves

v fmt -verify .
v vet .
v test .
```

The symlink is how V finds a module that is not installed. All three commands
should pass on a clean checkout; if they do not, that is a bug and worth an issue
on its own.

## Before you start

**For a bug fix**, just send the pull request. A failing test in the first commit
and the fix in the second makes review easy, but one commit is fine.

**For a new feature**, open an issue first. The scope of this project is
deliberately bounded - it negotiates and carries a NetherNet connection, it does
not implement the Bedrock protocol that runs over one - and it is better to find
out that something is out of scope before you write it.

**For a new signalling transport** - Xbox Live, Realms, anything that is not the
LAN - implement the `Signaling` interface rather than changing `dial` or
`listen`. That interface exists precisely so a new transport does not touch the
negotiation.

**For anything security-sensitive**, read [SECURITY.md](SECURITY.md) first. If
you have found a vulnerability, do not open a pull request that fixes it in
public; report it privately.

## What a good change looks like

### It matches what the game actually does

This module talks to a closed-source implementation. When the two disagree, the
game is right and we are wrong, however sensible our version looks. So:

- If a change makes the wire format differ from vanilla, say in the commit
  message which vanilla behaviour it matches and how you observed it.
- If a constant comes from the game - a port, a version byte, a segment size, an
  error code - put the value in a named constant with a comment saying where it
  comes from, not inline.
- The Go and PHP implementations under `inspirations/` are the reference for what
  vanilla does. Do not copy them structurally; V is not Go.

### It is tested

Every change to a wire format or to negotiation needs tests. Concretely:

- A new packet or structure needs a round-trip test and tests for each way the
  input can be malformed. It must not panic on anything.
- A change to negotiation, signalling order or the transports needs a test that
  drives two real endpoints. `discovery/integration_test.v` is the pattern: both
  ends in one process over loopback, through discovery, the offer and answer, and
  a message in each direction.
- A change to identity handling needs a test that the assertion fails when it
  should - against a description it did not sign, under a key it was not made
  with, or with a token signed by somebody else.
- A bug fix needs a test that fails before it and passes after.

Tests are not a formality here. The failures that matter in this domain are in
ordering, timing and hostile input, and none of them show up in code review. Two
of the bugs this module has already had were candidates signalled a few
milliseconds too early, which no amount of reading the diff would have found.

### It handles hostile input

Everything from the network is attacker-controlled - a discovery packet, a
signal, an SDP, a data channel message - and all of it arrives before the peer
has been authenticated. When you write a decoder:

- Read through `discovery.Reader`. Do not index a slice directly.
- If a length field from the wire decides how much you allocate, give it a limit
  and document the limit on the constant itself.
- Return an error. Do not panic, and do not return a partially decoded structure.
- If a peer sends something that cannot be recovered from - a segment that breaks
  the sequence, a data channel we did not ask for - close the connection rather
  than continuing with state you no longer trust.

### It keeps the identity binding intact

The point of the `a=identity` attribute is that an assertion is tied to one peer
connection. Anything that verifies a signature against a payload other than the
fingerprints of the description it arrived in breaks that, and will be rejected.
The payload is rebuilt from the SDP text rather than from parsed values for the
same reason: re-rendering a fingerprint can change its case or its separators,
and then a valid signature fails or an invalid one passes.

### It is commented where it needs to be

Comments explain *why*. If a line exists because of something the game does, say
so:

```v
// The game's parser expects every candidate to name the credentials it belongs
// to, and ignores candidates without the generation and network-cost
// extensions.
parts << ['generation', '0', 'ufrag', ufrag, 'network-id', id.str()]
```

Do not comment what the code already says. `// increment the counter` above `i++`
is noise.

Public API gets a doc comment whose first sentence starts with the identifier
being documented.

### It is formatted

`v fmt -w .` before committing. CI verifies it.

## Running the tests

```sh
v test .                            # everything
v test discovery                    # one module
v test discovery/integration_test.v # one file
```

The integration test opens loopback sockets and takes a couple of seconds. If it
is flaky on your machine, say so in an issue rather than adding a sleep - a test
that needs a longer timeout to pass is usually telling you something.

`WEBRTC_LOG_LEVEL=debug` turns on the transport logging in the examples, which is
the fastest way to see what ICE is actually doing. On a host with several
interfaces - a docker bridge alongside the real network - set
`NETHERNET_INTERFACE=lo` when running the examples against another process on the
same machine.

## Commit messages

Conventional commits, one purpose per commit:

```
feat(discovery): advertise server data version 7
fix(dial): trickle candidates only after the answer is applied
docs(readme): explain the identity binding
test(conn): cover the out-of-sequence segment path
```

Types in use: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`,
`chore`. The scope is the file or the area the change belongs to.

Keep the subject under 72 characters and in the imperative. If the change needs
explaining, put it in the body - what it does and why, not how.

## Pull requests

- One logical change per pull request. A refactor and a fix in the same diff is
  two pull requests.
- Do not reformat code you are not otherwise changing; it buries the real change
  and destroys `git blame`.
- CI must be green. It runs the same format check, vet and test suite you can run
  locally, on Linux and macOS.

Review is about whether it matches the game, whether it is safe against hostile
input, and whether the next person will understand it. Expect questions about
ordering and edge cases; they are not an objection to the change.

## If you found a better design

Say so, in an issue. Do not fold a redesign into an unrelated pull request. A
better idea is welcome; a large diff that changes several things at once is hard
to review and harder to revert.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

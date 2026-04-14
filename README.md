# Noise.jl

Julia-native Noise Protocol Framework implementation.

Started by contributors from [TODOforAI](https://todofor.ai).

Port of [noise-zig](../noise-zig), which itself follows the [noise-c](../benchmarks/zig-transport-compare/vendor/noise-c) reference.

## Status

Fully implemented and tested.

The codebase also includes some static-compilation-oriented design choices.
For example, `src/types.jl` avoids `Union{Nothing, ...}` in a few places to stay friendlier to `StaticCompiler.jl`.

- X25519 DH (libsodium), ChaCha20-Poly1305 AEAD (libsodium), BLAKE2s-256 (pure Julia), HMAC-BLAKE2s, HKDF
- `CipherState`, `SymmetricState`, `HandshakeState`, `TransportState`
- All four patterns: `IK`, `KK`, `XX`, `NX`
- 21 passing test sets (matching noise-zig)

## Supported patterns

| Pattern | Initiator | Responder | Use case |
|---------|-----------|-----------|----------|
| `IK` | has `s`, knows `rs` | has `s` | client knows server static key, client is authenticated |
| `KK` | has `s`, knows `rs` | has `s`, knows `rs` | both peers know each other's static key |
| `XX` | has `s` | has `s` | mutual auth, no prior key knowledge |
| `NX` | no static key | has `s` | server transmits static key, client is anonymous |

## Usage

```julia
using Noise

# XX: both sides authenticate, no prior key knowledge
i_kp = generate_keypair()
r_kp = generate_keypair()

i = handshake_init(HandshakeConfig(pattern=xx, role=initiator, s=i_kp))
r = handshake_init(HandshakeConfig(pattern=xx, role=responder, s=r_kp))

read_message!(r, write_message!(i))        # -> e
read_message!(i, write_message!(r))        # <- e, ee, s, es
read_message!(r, write_message!(i))        # -> s, se

it = handshake_split(i)
rt = handshake_split(r)

pt = transport_read!(rt, transport_write!(it, Vector{UInt8}("hello")))
# pt == UInt8[0x68, 0x65, 0x6c, 0x6c, 0x6f]  ("hello")
```

## Architecture

Mirrors the noise-zig source structure:

| Julia file | Zig equivalent | Description |
|------------|---------------|-------------|
| `src/types.jl` | `types.zig` | `Role`, `KeyPair`, `PublicKey`, `SecretKey` |
| `src/constants.jl` | `constants.zig` | Protocol constants (key/hash/nonce lengths) |
| `src/crypto.jl` | `crypto.zig` | BLAKE2s, HMAC, HKDF, X25519, ChaCha20-Poly1305 |
| `src/patterns.jl` | `patterns.zig` | Pattern descriptors for IK, KK, XX, NX |
| `src/cipher_state.jl` | `cipher_state.zig` | AEAD encrypt/decrypt with nonce tracking |
| `src/symmetric_state.jl` | `symmetric_state.zig` | Chaining key + handshake hash management |
| `src/handshake_state.jl` | `handshake_state.zig` | Full handshake state machine |
| `src/transport_state.jl` | `transport_state.zig` | Post-handshake send/recv |

## Crypto backends

- **BLAKE2s-256**: Pure Julia (RFC 7693) — libsodium only provides BLAKE2b
- **HMAC-BLAKE2s / HKDF**: Pure Julia (built on BLAKE2s, matching noise-c `hashstate.c`)
- **X25519**: libsodium via `ccall` (`crypto_scalarmult_curve25519`)
- **ChaCha20-Poly1305 IETF**: libsodium via `ccall` (`crypto_aead_chacha20poly1305_ietf`)

## Not yet implemented

- Zeroization of secrets and ephemeral keys
- Official Noise test vectors
- Packet framing examples (UDP/TCP/WebSocket)

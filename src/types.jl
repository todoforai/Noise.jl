# Types matching noise-zig/src/types.zig
# Static-compilation friendly: concrete types, no Union, fixed-size keys

"""Role in the Noise handshake: initiator or responder."""
@enum Role initiator responder

const PublicKey = NTuple{32, UInt8}
const SecretKey = NTuple{32, UInt8}
const Key32 = NTuple{32, UInt8}

const ZERO_KEY32 = ntuple(_ -> UInt8(0), 32)

struct KeyPair
    public_key::PublicKey
    secret_key::SecretKey
end

const EMPTY_KEYPAIR = KeyPair(ZERO_KEY32, ZERO_KEY32)

"""Optional KeyPair — avoids Union{Nothing, KeyPair} for static compilation."""
struct OptionalKeyPair
    value::KeyPair
    present::Bool
end

OptionalKeyPair() = OptionalKeyPair(EMPTY_KEYPAIR, false)
OptionalKeyPair(kp::KeyPair) = OptionalKeyPair(kp, true)

@inline is_present(o::OptionalKeyPair) = o.present
@inline function unwrap(o::OptionalKeyPair)::KeyPair
    o.present || error("MissingKey")
    o.value
end

"""Optional PublicKey — avoids Union{Nothing, PublicKey} for static compilation."""
struct OptionalPublicKey
    value::PublicKey
    present::Bool
end

OptionalPublicKey() = OptionalPublicKey(ZERO_KEY32, false)
OptionalPublicKey(pk::PublicKey) = OptionalPublicKey(pk, true)

@inline is_present(o::OptionalPublicKey) = o.present
@inline function unwrap(o::OptionalPublicKey)::PublicKey
    o.present || error("MissingKey")
    o.value
end

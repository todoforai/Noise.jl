# HandshakeState matching noise-zig/src/handshake_state.zig
# Static-compilation friendly: no Union types, MVector for fixed-size buffers

struct HandshakeConfig
    pattern::Pattern
    role::Role
    prologue::Vector{UInt8}
    s::OptionalKeyPair
    rs::OptionalPublicKey

    HandshakeConfig(; pattern::Pattern, role::Role, prologue::AbstractVector{UInt8}=UInt8[],
                    s::Union{Nothing, KeyPair}=nothing,
                    rs::Union{Nothing, NTuple{32,UInt8}}=nothing) =
        new(pattern, role, collect(UInt8, prologue),
            s === nothing ? OptionalKeyPair() : OptionalKeyPair(s),
            rs === nothing ? OptionalPublicKey() : OptionalPublicKey(rs))
end

mutable struct HandshakeState
    config::HandshakeConfig
    symmetric::SymmetricState
    e::OptionalKeyPair
    re::OptionalPublicKey
    rs::OptionalPublicKey
    message_index::Int
    complete::Bool
end

function handshake_init(config::HandshakeConfig)::HandshakeState
    validate_config(config)
    desc = descriptor(config.pattern)
    name, name_len = protocol_name_tuple(desc)
    sym = symmetric_state_init(name, name_len)
    if !isempty(config.prologue)
        mix_hash!(sym, config.prologue)
    end
    hs = HandshakeState(config, sym, OptionalKeyPair(), OptionalPublicKey(), config.rs, 0, false)
    apply_pre_messages!(hs, desc)
    hs
end

is_complete(hs::HandshakeState) = hs.complete

function write_message!(hs::HandshakeState, payload::AbstractVector{UInt8}=UInt8[])::Vector{UInt8}
    hs.complete && error("HandshakeComplete")
    is_write_turn(hs) || error("InvalidTurn: not our turn to write")

    desc = descriptor(hs.config.pattern)
    tokens = message_tokens(desc, hs.message_index + 1)
    token_count = message_token_count(desc, hs.message_index + 1)
    out = UInt8[]
    pk = MVector{32, UInt8}(undef)
    for ti in 1:token_count
        token = tokens[ti]
        if token == e
            if !is_present(hs.e)
                hs.e = OptionalKeyPair(generate_keypair())
            end
            _copy_key!(pk, unwrap(hs.e).public_key)
            append!(out, pk)
            mix_hash!(hs.symmetric, pk)
        elseif token == s
            is_present(hs.config.s) || error("MissingStaticKey")
            _copy_key!(pk, unwrap(hs.config.s).public_key)
            ct = encrypt_and_hash!(hs.symmetric, pk)
            append!(out, ct)
        elseif token == ee || token == es || token == se || token == ss
            mix_dh!(hs, token)
        end
    end
    ct = encrypt_and_hash!(hs.symmetric, payload)
    append!(out, ct)
    advance!(hs)
    out
end

function read_message!(hs::HandshakeState, msg::AbstractVector{UInt8})::Vector{UInt8}
    hs.complete && error("HandshakeComplete")
    !is_write_turn(hs) || error("InvalidTurn: not our turn to read")

    desc = descriptor(hs.config.pattern)
    tokens = message_tokens(desc, hs.message_index + 1)
    token_count = message_token_count(desc, hs.message_index + 1)
    off = 1
    for ti in 1:token_count
        token = tokens[ti]
        if token == e
            remaining = length(msg) - off + 1
            remaining >= DH_LEN || error("TruncatedMessage")
            hs.re = OptionalPublicKey(NTuple{32,UInt8}(@view msg[off:off+DH_LEN-1]))
            pk = MVector{32, UInt8}(unwrap(hs.re))
            mix_hash!(hs.symmetric, pk)
            off += DH_LEN
        elseif token == s
            extra = has_key(hs.symmetric.cipher) ? TAG_LEN : 0
            size = DH_LEN + extra
            remaining = length(msg) - off + 1
            remaining >= size || error("TruncatedMessage")
            pk_bytes = decrypt_and_hash!(hs.symmetric, @view msg[off:off+size-1])
            hs.rs = OptionalPublicKey(NTuple{32,UInt8}(pk_bytes))
            off += size
        elseif token == ee || token == es || token == se || token == ss
            mix_dh!(hs, token)
        end
    end
    plaintext = decrypt_and_hash!(hs.symmetric, @view msg[off:end])
    advance!(hs)
    plaintext
end

function handshake_split(hs::HandshakeState)::TransportState
    hs.complete || error("HandshakeNotComplete")
    pair = symmetric_split(hs.symmetric)
    transport_state_init(hs.config.role, pair.initiator, pair.responder)
end

expected_message_count(hs::HandshakeState) = num_messages(descriptor(hs.config.pattern))

# ─── Internal helpers ────────────────────────────────────────────────────────

@inline function _copy_key!(dst::MVector{32, UInt8}, src::NTuple{32, UInt8})
    @inbounds for i in 1:32; dst[i] = src[i]; end
end

function apply_pre_messages!(hs::HandshakeState, desc::Descriptor)
    for i in 1:length(desc.pre_i)
        mix_pre_message!(hs, desc.pre_i[i], initiator)
    end
    for i in 1:length(desc.pre_r)
        mix_pre_message!(hs, desc.pre_r[i], responder)
    end
end

function mix_pre_message!(hs::HandshakeState, token::Token, role::Role)
    if token == s
        pk_tuple = static_key_for(hs, role)
        pk = MVector{32, UInt8}(pk_tuple)
        mix_hash!(hs.symmetric, pk)
    elseif token == e
        error("UnsupportedPreMessage: ephemeral pre-messages not supported")
    else
        error("InvalidPreMessageToken")
    end
end

function static_key_for(hs::HandshakeState, role::Role)::PublicKey
    if role == hs.config.role
        is_present(hs.config.s) || error("MissingStaticKey")
        return unwrap(hs.config.s).public_key
    else
        is_present(hs.rs) || error("MissingRemoteStaticKey")
        return unwrap(hs.rs)
    end
end

function is_write_turn(hs::HandshakeState)::Bool
    sender_role(hs.message_index) == hs.config.role
end

function advance!(hs::HandshakeState)
    hs.message_index += 1
    hs.complete = hs.message_index >= expected_message_count(hs)
end

sender_role(message_index::Int)::Role = message_index % 2 == 0 ? initiator : responder

function mix_dh!(hs::HandshakeState, token::Token)
    shared = if token == ee
        x25519_dh(local_ephemeral_secret(hs), remote_ephemeral(hs))
    elseif token == es
        if hs.config.role == initiator
            x25519_dh(local_ephemeral_secret(hs), remote_static(hs))
        else
            x25519_dh(local_static_secret(hs), remote_ephemeral(hs))
        end
    elseif token == se
        if hs.config.role == initiator
            x25519_dh(local_static_secret(hs), remote_ephemeral(hs))
        else
            x25519_dh(local_ephemeral_secret(hs), remote_static(hs))
        end
    elseif token == ss
        x25519_dh(local_static_secret(hs), remote_static(hs))
    else
        error("InvalidDhToken")
    end
    mix_key!(hs.symmetric, shared)
end

function local_ephemeral_secret(hs::HandshakeState)::SecretKey
    is_present(hs.e) || error("MissingEphemeralKey")
    unwrap(hs.e).secret_key
end

function local_static_secret(hs::HandshakeState)::SecretKey
    is_present(hs.config.s) || error("MissingStaticKey")
    unwrap(hs.config.s).secret_key
end

function remote_ephemeral(hs::HandshakeState)::PublicKey
    is_present(hs.re) || error("MissingRemoteEphemeralKey")
    unwrap(hs.re)
end

function remote_static(hs::HandshakeState)::PublicKey
    is_present(hs.rs) || error("MissingRemoteStaticKey")
    unwrap(hs.rs)
end

function validate_config(config::HandshakeConfig)
    p = config.pattern
    r = config.role
    if p == ik
        if r == initiator
            is_present(config.s) || error("MissingStaticKey")
            is_present(config.rs) || error("MissingRemoteStaticKey")
        else
            is_present(config.s) || error("MissingStaticKey")
        end
    elseif p == kk
        is_present(config.s) || error("MissingStaticKey")
        is_present(config.rs) || error("MissingRemoteStaticKey")
    elseif p == xx
        # No requirements
    elseif p == nx
        if r == responder
            is_present(config.s) || error("MissingStaticKey")
        end
    end
end

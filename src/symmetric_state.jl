# SymmetricState matching noise-zig/src/symmetric_state.zig
# Static-compilation friendly: MVector for fixed-size hash/key state
# BLAKE2b: HASHLEN=64, KEY_LEN=32 (cipher key is TRUNCATE(HKDF output, 32)).

mutable struct SymmetricState
    ck::MVector{64, UInt8}  # chaining key, 64 bytes (HASHLEN)
    h::MVector{64, UInt8}   # handshake hash, 64 bytes (HASHLEN)
    cipher::CipherState
end

symmetric_state_init(name::String) = symmetric_state_init(Vector{UInt8}(codeunits(name)))

"""Init from tuple + length (zero-allocation path for compile-time protocol names)."""
function symmetric_state_init(name_tuple::NTuple{34, UInt8}, name_len::Int)::SymmetricState
    h = MVector{64, UInt8}(undef)
    if name_len <= HASH_LEN
        @inbounds for i in 1:name_len; h[i] = name_tuple[i]; end
        @inbounds for i in (name_len+1):HASH_LEN; h[i] = 0x00; end
    else
        # name_len > 64: hash it (protocol names are ≤34 chars, so this branch is unused)
        buf = MVector{34, UInt8}(undef)
        @inbounds for i in 1:name_len; buf[i] = name_tuple[i]; end
        blake2b_hash!(h, @view buf[1:name_len])
    end
    SymmetricState(MVector{64, UInt8}(h), h, CipherState())
end

function symmetric_state_init(name_bytes::AbstractVector{UInt8})::SymmetricState
    h = MVector{64, UInt8}(undef)
    if length(name_bytes) <= HASH_LEN
        @inbounds for i in 1:length(name_bytes); h[i] = name_bytes[i]; end
        @inbounds for i in (length(name_bytes)+1):HASH_LEN; h[i] = 0x00; end
    else
        blake2b_hash!(h, name_bytes)
    end
    SymmetricState(MVector{64, UInt8}(h), h, CipherState())
end

function mix_hash!(ss::SymmetricState, data::AbstractVector{UInt8})
    # H(ss.h || data) — feed both into BLAKE2b incrementally (no concat allocation)
    ctx = Blake2bContext()
    update!(ctx, ss.h)
    update!(ctx, data)
    digest!(ss.h, ctx)
end

# Truncate a 64-byte HKDF block to a 32-byte cipher key.
@inline function _truncate32(out64::AbstractVector{UInt8})::MVector{32, UInt8}
    k = MVector{32, UInt8}(undef)
    @inbounds for i in 1:32; k[i] = out64[i]; end
    k
end

function mix_key!(ss::SymmetricState, input_key_material::AbstractVector{UInt8})
    r = hkdf2(ss.ck, input_key_material)
    ss.ck .= r.out1
    ss.cipher = CipherState(_truncate32(r.out2))
end

function mix_key_and_hash!(ss::SymmetricState, input_key_material::AbstractVector{UInt8})
    r = hkdf3(ss.ck, input_key_material)
    ss.ck .= r.out1
    mix_hash!(ss, r.out2)
    ss.cipher = CipherState(_truncate32(r.out3))
end

function encrypt_and_hash!(ss::SymmetricState, plaintext::AbstractVector{UInt8})::Vector{UInt8}
    ciphertext = encrypt_with_ad!(ss.cipher, ss.h, plaintext)
    mix_hash!(ss, ciphertext)
    ciphertext
end

function decrypt_and_hash!(ss::SymmetricState, ciphertext::AbstractVector{UInt8})::Vector{UInt8}
    plaintext = decrypt_with_ad!(ss.cipher, ss.h, ciphertext)
    mix_hash!(ss, ciphertext)
    plaintext
end

function symmetric_split(ss::SymmetricState)
    # Split: both HKDF outputs become cipher keys (each truncated to 32).
    r = hkdf2(ss.ck, MVector{0, UInt8}())
    (initiator=CipherState(_truncate32(r.out1)), responder=CipherState(_truncate32(r.out2)))
end

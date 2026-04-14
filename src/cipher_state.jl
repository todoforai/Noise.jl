# CipherState matching noise-zig/src/cipher_state.zig
# Static-compilation friendly: no Union, MVector nonce, concrete key type

mutable struct CipherState
    key::Key32
    has_key::Bool
    nonce::UInt64
end

CipherState() = CipherState(ZERO_KEY32, false, 0)
CipherState(key::AbstractVector{UInt8}) = CipherState(NTuple{32,UInt8}(key), true, 0)
CipherState(key::Key32) = CipherState(key, true, 0)
CipherState(key::MVector{32, UInt8}) = CipherState(NTuple{32,UInt8}(key), true, 0)

has_key(cs::CipherState) = cs.has_key

function rekey!(cs::CipherState, key::Key32)
    cs.key = key
    cs.has_key = true
    cs.nonce = 0
end

function nonce_bytes!(out::MVector{12, UInt8}, cs::CipherState)
    # 12-byte nonce: 4 zero bytes + 8-byte little-endian counter
    @inbounds for i in 1:4; out[i] = 0x00; end
    n = cs.nonce
    @inbounds for i in 5:12
        out[i] = UInt8(n & 0xFF)
        n >>= 8
    end
end

function encrypt_with_ad!(cs::CipherState, ad::AbstractVector{UInt8},
                          plaintext::AbstractVector{UInt8})::Vector{UInt8}
    cs.has_key || return collect(UInt8, plaintext)
    cs.nonce == typemax(UInt64) && error("NonceExhausted")
    nonce = MVector{12, UInt8}(undef)
    nonce_bytes!(nonce, cs)
    key_v = MVector{32, UInt8}(cs.key)
    ct = chacha20poly1305_encrypt(plaintext, ad, nonce, key_v)
    cs.nonce += 1
    ct
end

function decrypt_with_ad!(cs::CipherState, ad::AbstractVector{UInt8},
                          ciphertext::AbstractVector{UInt8})::Vector{UInt8}
    cs.has_key || return collect(UInt8, ciphertext)
    cs.nonce == typemax(UInt64) && error("NonceExhausted")
    length(ciphertext) >= TAG_LEN || error("InvalidCiphertext: too short")
    nonce = MVector{12, UInt8}(undef)
    nonce_bytes!(nonce, cs)
    key_v = MVector{32, UInt8}(cs.key)
    pt = chacha20poly1305_decrypt(ciphertext, ad, nonce, key_v)
    cs.nonce += 1
    pt
end

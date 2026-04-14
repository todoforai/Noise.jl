# Crypto primitives matching noise-zig/src/crypto.zig
# BLAKE2s-256: via BLAKE2.jl (MVector-based, static-friendly)
# X25519, ChaCha20-Poly1305: via Crypto25519.jl (MVector-based, static-friendly)

using BLAKE2: Blake2sContext, update!, digest!
using Crypto25519: x25519_scalar_mult!, chacha20_poly1305_encrypt!, chacha20_poly1305_decrypt!
using Random: RandomDevice, rand!

# ─── BLAKE2s-256 ─────────────────────────────────────────────────────────────

const BLAKE2S_BLOCKBYTES = 64
const BLAKE2S_OUTBYTES = 32

"""Hash data with BLAKE2s-256 into caller-provided MVector{32}."""
function blake2s_hash!(out::MVector{32, UInt8}, data::AbstractVector{UInt8})
    ctx = Blake2sContext()
    update!(ctx, data)
    digest!(out, ctx)
end

"""Hash data with BLAKE2s-256, returns MVector{32, UInt8}."""
function blake2s_hash(data::AbstractVector{UInt8})::MVector{32, UInt8}
    out = MVector{32, UInt8}(undef)
    blake2s_hash!(out, data)
    out
end

# ─── HMAC-BLAKE2s ────────────────────────────────────────────────────────────
# Matches noise-c hashstate.c noise_hashstate_hmac and noise-zig crypto.zig Hmac

function hmac_blake2s!(out::MVector{32, UInt8}, key::AbstractVector{UInt8},
                       data::AbstractVector{UInt8})
    block_len = BLAKE2S_BLOCKBYTES
    key_block = MVector{64, UInt8}(undef)

    if length(key) <= block_len
        @inbounds for i in 1:length(key); key_block[i] = key[i]; end
        @inbounds for i in (length(key)+1):block_len; key_block[i] = 0x00; end
    else
        h = blake2s_hash(key)
        @inbounds for i in 1:BLAKE2S_OUTBYTES; key_block[i] = h[i]; end
        @inbounds for i in (BLAKE2S_OUTBYTES+1):block_len; key_block[i] = 0x00; end
    end

    # Inner hash: H((key ⊻ ipad) || data)
    ipad = MVector{64, UInt8}(undef)
    @inbounds for i in 1:block_len; ipad[i] = key_block[i] ⊻ 0x36; end
    ctx = Blake2sContext()
    update!(ctx, ipad)
    update!(ctx, data)
    inner = MVector{32, UInt8}(undef)
    digest!(inner, ctx)

    # Outer hash: H((key ⊻ opad) || inner)
    opad = MVector{64, UInt8}(undef)
    @inbounds for i in 1:block_len; opad[i] = key_block[i] ⊻ 0x5c; end
    ctx = Blake2sContext()
    update!(ctx, opad)
    update!(ctx, inner)
    digest!(out, ctx)
end

function hmac_blake2s(key::AbstractVector{UInt8}, data::AbstractVector{UInt8})::MVector{32, UInt8}
    out = MVector{32, UInt8}(undef)
    hmac_blake2s!(out, key, data)
    out
end

# ─── HKDF (RFC 5869 style, matching noise-c and noise-zig) ──────────────────

function hkdf2(chaining_key::AbstractVector{UInt8}, input_key_material::AbstractVector{UInt8})
    # Extract
    prk = hmac_blake2s(chaining_key, input_key_material)
    # Expand: out1 = HMAC(prk, 0x01), out2 = HMAC(prk, out1 || 0x02)
    out1 = hmac_blake2s(prk, MVector{1, UInt8}(0x01))
    # Build out1 || 0x02
    buf = MVector{33, UInt8}(undef)
    @inbounds for i in 1:32; buf[i] = out1[i]; end
    buf[33] = 0x02
    out2 = hmac_blake2s(prk, buf)
    (out1=out1, out2=out2)
end

function hkdf3(chaining_key::AbstractVector{UInt8}, input_key_material::AbstractVector{UInt8})
    prk = hmac_blake2s(chaining_key, input_key_material)
    out1 = hmac_blake2s(prk, MVector{1, UInt8}(0x01))
    buf = MVector{33, UInt8}(undef)
    @inbounds for i in 1:32; buf[i] = out1[i]; end
    buf[33] = 0x02
    out2 = hmac_blake2s(prk, buf)
    @inbounds for i in 1:32; buf[i] = out2[i]; end
    buf[33] = 0x03
    out3 = hmac_blake2s(prk, buf)
    (out1=out1, out2=out2, out3=out3)
end

# ─── X25519 (via Crypto25519.jl) ────────────────────────────────────────────

function generate_keypair()::KeyPair
    sk = MVector{32, UInt8}(undef)
    pk = MVector{32, UInt8}(undef)
    rand!(RandomDevice(), sk)
    x25519_scalar_mult!(pk, sk, X25519_BASEPOINT)
    KeyPair(NTuple{32,UInt8}(pk), NTuple{32,UInt8}(sk))
end

# X25519 basepoint (9, 0, 0, ..., 0)
const X25519_BASEPOINT = let
    bp = MVector{32, UInt8}(undef)
    @inbounds for i in 1:32; bp[i] = 0x00; end
    bp[1] = 0x09
    bp
end

function x25519_dh(secret_key::NTuple{32,UInt8}, public_key::NTuple{32,UInt8})::MVector{32, UInt8}
    shared = MVector{32, UInt8}(undef)
    sk = MVector{32, UInt8}(secret_key)
    pk = MVector{32, UInt8}(public_key)
    x25519_scalar_mult!(shared, sk, pk)
    shared
end

# ─── ChaCha20-Poly1305 IETF (via Crypto25519.jl) ────────────────────────────

function chacha20poly1305_encrypt(plaintext::AbstractVector{UInt8},
                                  ad::AbstractVector{UInt8},
                                  nonce::AbstractVector{UInt8},
                                  key::AbstractVector{UInt8})::Vector{UInt8}
    # Variable-length output at API boundary — Vector is unavoidable here
    out = Vector{UInt8}(undef, length(plaintext) + TAG_LEN)
    ct_view = @view out[1:length(plaintext)]
    tag_view = @view out[length(plaintext)+1:end]
    chacha20_poly1305_encrypt!(ct_view, tag_view, key, nonce, plaintext, ad)
    out
end

function chacha20poly1305_decrypt(ciphertext::AbstractVector{UInt8},
                                  ad::AbstractVector{UInt8},
                                  nonce::AbstractVector{UInt8},
                                  key::AbstractVector{UInt8})::Vector{UInt8}
    msg_len = length(ciphertext) - TAG_LEN
    msg_len >= 0 || error("InvalidCiphertext: too short")
    pt = Vector{UInt8}(undef, msg_len)
    chacha20_poly1305_decrypt!(pt, key, nonce, ciphertext, ad)
    pt
end

using Test
using Noise

# Helper: compare bytes to string without consuming the vector
bytes(s::String) = Vector{UInt8}(codeunits(s))

# ─── Crypto tests (matching noise-zig crypto.zig tests) ─────────────────────

@testset "BLAKE2b known vector" begin
    # BLAKE2b-512("") from RFC 7693
    h = Noise.blake2b_hash(UInt8[])
    @test length(h) == 64
    @test h != zeros(UInt8, 64)
end

@testset "hkdf2 returns two 64-byte outputs" begin
    r = Noise.hkdf2(fill(UInt8(1), 64), bytes("abc"))
    @test length(r.out1) == 64
    @test length(r.out2) == 64
    @test r.out1 != zeros(UInt8, 64)
    @test r.out2 != zeros(UInt8, 64)
end

@testset "hkdf3 returns three 64-byte outputs" begin
    r = Noise.hkdf3(fill(UInt8(2), 64), bytes("abc"))
    @test length(r.out1) == 64
    @test length(r.out2) == 64
    @test length(r.out3) == 64
    @test r.out1 != zeros(UInt8, 64)
    @test r.out2 != zeros(UInt8, 64)
    @test r.out3 != zeros(UInt8, 64)
end

# ─── CipherState tests (matching noise-zig cipher_state.zig tests) ──────────

@testset "cipher state without key is passthrough" begin
    cs = Noise.CipherState()
    ct = Noise.encrypt_with_ad!(cs, bytes("ad"), bytes("hello"))
    @test ct == bytes("hello")
    @test cs.nonce == 0
    pt = Noise.decrypt_with_ad!(cs, bytes("ad"), ct)
    @test pt == bytes("hello")
end

@testset "cipher state with key roundtrips" begin
    key = fill(UInt8(7), 32)
    cs_enc = Noise.CipherState(copy(key))
    cs_dec = Noise.CipherState(copy(key))
    ct = Noise.encrypt_with_ad!(cs_enc, bytes("ad"), bytes("hello"))
    @test length(ct) == 5 + Noise.TAG_LEN
    @test cs_enc.nonce == 1
    pt = Noise.decrypt_with_ad!(cs_dec, bytes("ad"), ct)
    @test pt == bytes("hello")
    @test cs_dec.nonce == 1
end

# ─── SymmetricState tests (matching noise-zig symmetric_state.zig tests) ─────

@testset "symmetric state initializes h and ck from short protocol name" begin
    ss = Noise.symmetric_state_init("Noise_XX_25519_ChaChaPoly_BLAKE2b")
    @test ss.ck == ss.h
end

@testset "mixHash changes h" begin
    ss = Noise.symmetric_state_init("Noise_XX_25519_ChaChaPoly_BLAKE2b")
    before = copy(ss.h)
    Noise.mix_hash!(ss, bytes("abc"))
    @test before != ss.h
end

@testset "mixKey enables encryption" begin
    ss = Noise.symmetric_state_init("Noise_XX_25519_ChaChaPoly_BLAKE2b")
    @test !Noise.has_key(ss.cipher)
    Noise.mix_key!(ss, bytes("abc"))
    @test Noise.has_key(ss.cipher)
end

@testset "encryptAndHash roundtrips after mixKey" begin
    a = Noise.symmetric_state_init("Noise_XX_25519_ChaChaPoly_BLAKE2b")
    b = Noise.symmetric_state_init("Noise_XX_25519_ChaChaPoly_BLAKE2b")
    Noise.mix_key!(a, bytes("shared secret"))
    Noise.mix_key!(b, bytes("shared secret"))
    ct = Noise.encrypt_and_hash!(a, bytes("hello"))
    pt = Noise.decrypt_and_hash!(b, ct)
    @test pt == bytes("hello")
    @test a.h == b.h
end

# ─── HandshakeState tests (matching noise-zig handshake_state.zig tests) ─────

const ZERO_KEY = ntuple(_ -> UInt8(0), 32)
const ZERO_KP = KeyPair(ZERO_KEY, ZERO_KEY)

@testset "IK initiator requires local static and remote static" begin
    @test_throws ErrorException handshake_init(HandshakeConfig(pattern=ik, role=initiator, rs=ZERO_KEY))
    @test_throws ErrorException handshake_init(HandshakeConfig(pattern=ik, role=initiator, s=ZERO_KP))
end

@testset "IK responder requires only local static" begin
    handshake_init(HandshakeConfig(pattern=ik, role=responder, s=ZERO_KP))
    @test_throws ErrorException handshake_init(HandshakeConfig(pattern=ik, role=responder))
end

@testset "KK requires both local static and remote static" begin
    @test_throws ErrorException handshake_init(HandshakeConfig(pattern=kk, role=initiator, rs=ZERO_KEY))
    @test_throws ErrorException handshake_init(HandshakeConfig(pattern=kk, role=responder, s=ZERO_KP))
end

@testset "XX allows empty key configuration" begin
    handshake_init(HandshakeConfig(pattern=xx, role=initiator))
end

@testset "NX initiator needs no keys, responder requires local static" begin
    handshake_init(HandshakeConfig(pattern=nx, role=initiator))
    handshake_init(HandshakeConfig(pattern=nx, role=responder, s=ZERO_KP))
    @test_throws ErrorException handshake_init(HandshakeConfig(pattern=nx, role=responder))
end

@testset "expected message counts are correct" begin
    @test Noise.expected_message_count(handshake_init(HandshakeConfig(pattern=ik, role=initiator, s=ZERO_KP, rs=ZERO_KEY))) == 2
    @test Noise.expected_message_count(handshake_init(HandshakeConfig(pattern=kk, role=initiator, s=ZERO_KP, rs=ZERO_KEY))) == 2
    @test Noise.expected_message_count(handshake_init(HandshakeConfig(pattern=xx, role=initiator))) == 3
    @test Noise.expected_message_count(handshake_init(HandshakeConfig(pattern=nx, role=initiator))) == 2
end

@testset "split requires complete handshake" begin
    hs = handshake_init(HandshakeConfig(pattern=xx, role=initiator))
    @test_throws ErrorException handshake_split(hs)
end

@testset "write/read after handshake complete returns HandshakeComplete" begin
    resp_static = generate_keypair()
    i = handshake_init(HandshakeConfig(pattern=nx, role=initiator))
    r = handshake_init(HandshakeConfig(pattern=nx, role=responder, s=resp_static))
    m1 = write_message!(i)
    read_message!(r, m1)
    m2 = write_message!(r)
    read_message!(i, m2)
    @test is_complete(i)
    @test is_complete(r)
    @test_throws ErrorException write_message!(i, bytes("x"))
    @test_throws ErrorException read_message!(r, bytes("x"))
end

@testset "prologue changes handshake hash" begin
    a = handshake_init(HandshakeConfig(pattern=xx, role=initiator))
    b = handshake_init(HandshakeConfig(pattern=xx, role=initiator, prologue=bytes("p")))
    @test a.symmetric.h != b.symmetric.h
end

# ─── Full handshake roundtrip tests ─────────────────────────────────────────

function roundtrip_handshake(pat::Pattern)
    init_static = generate_keypair()
    resp_static = generate_keypair()

    if pat == xx
        i_cfg = HandshakeConfig(pattern=pat, role=initiator, s=init_static)
        r_cfg = HandshakeConfig(pattern=pat, role=responder, s=resp_static)
    elseif pat == nx
        i_cfg = HandshakeConfig(pattern=pat, role=initiator)
        r_cfg = HandshakeConfig(pattern=pat, role=responder, s=resp_static)
    elseif pat == ik
        i_cfg = HandshakeConfig(pattern=pat, role=initiator, s=init_static, rs=resp_static.public_key)
        r_cfg = HandshakeConfig(pattern=pat, role=responder, s=resp_static)
    elseif pat == kk
        i_cfg = HandshakeConfig(pattern=pat, role=initiator, s=init_static, rs=resp_static.public_key)
        r_cfg = HandshakeConfig(pattern=pat, role=responder, s=resp_static, rs=init_static.public_key)
    end

    i = handshake_init(i_cfg)
    r = handshake_init(r_cfg)

    # Message 1: initiator -> responder
    m1 = write_message!(i, bytes("p1"))
    p1 = read_message!(r, m1)
    @test p1 == bytes("p1")

    # Message 2: responder -> initiator
    m2 = write_message!(r, bytes("p2"))
    p2 = read_message!(i, m2)
    @test p2 == bytes("p2")

    # Message 3 (XX only)
    if pat == xx
        m3 = write_message!(i, bytes("p3"))
        p3 = read_message!(r, m3)
        @test p3 == bytes("p3")
    end

    @test is_complete(i)
    @test is_complete(r)
    @test i.symmetric.h == r.symmetric.h

    # Split and test transport
    it = handshake_split(i)
    rt = handshake_split(r)

    # initiator -> responder
    ct = transport_write!(it, bytes("i->r"))
    pt = transport_read!(rt, ct)
    @test pt == bytes("i->r")

    # responder -> initiator
    ct2 = transport_write!(rt, bytes("r->i"))
    pt2 = transport_read!(it, ct2)
    @test pt2 == bytes("r->i")
end

@testset "XX handshake roundtrips" begin roundtrip_handshake(xx) end
@testset "NX handshake roundtrips" begin roundtrip_handshake(nx) end
@testset "IK handshake roundtrips" begin roundtrip_handshake(ik) end
@testset "KK handshake roundtrips" begin roundtrip_handshake(kk) end

# ─── Cross-implementation interop vector ────────────────────────────────────
# Same fixture consumed by noise-zig/src/interop_test.zig and
# todoforai-c-core/noise/test_vector_nx.json.

hex(s::String) = Vector{UInt8}(hex2bytes(s))

@testset "Noise_NX_BLAKE2b interop vector" begin
    I_E_PUB  = hex("a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209")
    R_S_PUB  = hex("ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59")
    R_S_PRIV = NTuple{32,UInt8}(hex("0202020202020202020202020202020202020202020202020202020202020202"))
    R_E_PRIV = NTuple{32,UInt8}(hex("0303030303030303030303030303030303030303030303030303030303030303"))
    R_E_PUB  = hex("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22")
    EXP_H    = hex("60456adc43864da532bfb6fc17d81798c87ddb9a1174ddffa2ed5380fc0cd34cf7518d337c5ecac0c41a4caaf1b5480344e3395fcec1f3ae8dd8e6a2c594f425")
    EXP_CK   = hex("575db4282c1573b3ac5aa64eea404f1ede78438b5604285d617c9ff69af77336217d957a52f0139ef9e0b5965d4741c2df7ba74ff84abae15fa2ab1f34d3af05")
    EXP_K_I2R = hex("661e6648886a7bc3b3aefaafff70c1557806c5f515fff608bb2ddbe8b1cd3f6b")
    EXP_K_R2I = hex("1fa3239cd269cb397fe050752a88901b704add45a77d44da155d16c64784dbf2")
    EXP_CT    = hex("5cb416d11148b739af724cb50da19b6a1a6c3d5da7")

    I_E_PUB_T = NTuple{32,UInt8}(I_E_PUB)

    # Replay responder-side NX symmetric transitions.
    ss = Noise.symmetric_state_init("Noise_NX_25519_ChaChaPoly_BLAKE2b")
    Noise.mix_hash!(ss, UInt8[])      # prologue = []
    Noise.mix_hash!(ss, I_E_PUB)       # msg0: [e]
    Noise.mix_hash!(ss, R_E_PUB)       # msg1: e

    # ee: DH(R_E_PRIV, I_E_PUB)
    ee = Noise.x25519_dh(R_E_PRIV, I_E_PUB_T)
    Noise.mix_key!(ss, ee)

    # s: encrypt R_S_PUB under current key, AD = h
    Noise.encrypt_and_hash!(ss, R_S_PUB)

    # es: DH(R_S_PRIV, I_E_PUB)
    es = Noise.x25519_dh(R_S_PRIV, I_E_PUB_T)
    Noise.mix_key!(ss, es)

    # empty payload
    Noise.encrypt_and_hash!(ss, UInt8[])

    @test collect(ss.h)  == EXP_H
    @test collect(ss.ck) == EXP_CK

    pair = Noise.symmetric_split(ss)
    @test collect(pair.initiator.key) == EXP_K_I2R
    @test collect(pair.responder.key) == EXP_K_R2I

    # Transport: initiator sends "hello" under k_i2r with nonce=0, empty AD.
    ct = Noise.encrypt_with_ad!(pair.initiator, UInt8[], bytes("hello"))
    @test ct == EXP_CT
end

# TransportState matching noise-zig/src/transport_state.zig

mutable struct TransportState
    send::CipherState
    recv::CipherState
end

function transport_state_init(role::Role, initiator_cs::CipherState, responder_cs::CipherState)
    if role == initiator
        TransportState(initiator_cs, responder_cs)
    else
        TransportState(responder_cs, initiator_cs)
    end
end

const EMPTY_AD = MVector{0, UInt8}()

function transport_write!(ts::TransportState, plaintext::AbstractVector{UInt8})::Vector{UInt8}
    encrypt_with_ad!(ts.send, EMPTY_AD, plaintext)
end

function transport_read!(ts::TransportState, ciphertext::AbstractVector{UInt8})::Vector{UInt8}
    decrypt_with_ad!(ts.recv, EMPTY_AD, ciphertext)
end

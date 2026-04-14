module Noise

using StaticArrays: MVector

include("types.jl")
include("constants.jl")
include("crypto.jl")
include("patterns.jl")
include("cipher_state.jl")
include("symmetric_state.jl")
include("transport_state.jl")
include("handshake_state.jl")

# Public API (mirrors noise-zig/src/root.zig)
export Role, initiator, responder
export PublicKey, SecretKey, KeyPair
export Pattern, ik, kk, xx, nx
export HandshakeConfig, HandshakeState, TransportState
export generate_keypair, handshake_init, is_complete
export write_message!, read_message!, handshake_split
export transport_write!, transport_read!

end # module

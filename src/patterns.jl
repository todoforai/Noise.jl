# Patterns matching noise-zig/src/patterns.zig
# Static-compilation friendly: all const tuples, no heap allocation

@enum Pattern ik kk xx nx
@enum Token e s ee es se ss

struct Descriptor{N_PRE_I, N_PRE_R, N_MSG}
    protocol_name::NTuple{34, UInt8}  # max "Noise_XX_25519_ChaChaPoly_BLAKE2s" = 34 chars
    name_len::Int
    pre_i::NTuple{N_PRE_I, Token}
    pre_r::NTuple{N_PRE_R, Token}
    messages::NTuple{N_MSG, NTuple{4, Token}}  # max 4 tokens per message
    message_lengths::NTuple{N_MSG, Int}         # actual token count per message
end

@inline num_messages(d::Descriptor) = length(d.messages)
@inline message_tokens(d::Descriptor, i::Int) = d.messages[i]
@inline message_token_count(d::Descriptor, i::Int) = d.message_lengths[i]

# Helper: pad a string to NTuple{34, UInt8}
@inline function _name_tuple(s::String)
    bytes = codeunits(s)
    n = length(bytes)
    ntuple(i -> i <= n ? UInt8(bytes[i]) : UInt8(0), 34)
end

# Helper: pad token list to NTuple{4, Token}
@inline _tok4(a) = (a, e, e, e)
@inline _tok4(a, b) = (a, b, e, e)
@inline _tok4(a, b, c) = (a, b, c, e)
@inline _tok4(a, b, c, d) = (a, b, c, d)

# IK: pre_i=[], pre_r=[s], msgs=[[e,es,s,ss], [e,ee,se]]
const DESC_IK = Descriptor{0, 1, 2}(
    _name_tuple("Noise_IK_25519_ChaChaPoly_BLAKE2s"), 34,
    (), (s,),
    (_tok4(e, es, s, ss), _tok4(e, ee, se)),
    (4, 3))

# KK: pre_i=[s], pre_r=[s], msgs=[[e,es,ss], [e,ee,se]]
const DESC_KK = Descriptor{1, 1, 2}(
    _name_tuple("Noise_KK_25519_ChaChaPoly_BLAKE2s"), 34,
    (s,), (s,),
    (_tok4(e, es, ss), _tok4(e, ee, se)),
    (3, 3))

# XX: pre_i=[], pre_r=[], msgs=[[e], [e,ee,s,es], [s,se]]
const DESC_XX = Descriptor{0, 0, 3}(
    _name_tuple("Noise_XX_25519_ChaChaPoly_BLAKE2s"), 34,
    (), (),
    (_tok4(e), _tok4(e, ee, s, es), _tok4(s, se)),
    (1, 4, 2))

# NX: pre_i=[], pre_r=[], msgs=[[e], [e,ee,s,es]]
const DESC_NX = Descriptor{0, 0, 2}(
    _name_tuple("Noise_NX_25519_ChaChaPoly_BLAKE2s"), 34,
    (), (),
    (_tok4(e), _tok4(e, ee, s, es)),
    (1, 4))

function descriptor(pattern::Pattern)
    pattern == ik && return DESC_IK
    pattern == kk && return DESC_KK
    pattern == xx && return DESC_XX
    pattern == nx && return DESC_NX
    error("Unknown pattern")
end

"""Return protocol name as a view-compatible tuple + length (no allocation)."""
@inline protocol_name_tuple(d::Descriptor) = (d.protocol_name, d.name_len)

function protocol_name_bytes(d::Descriptor)::Vector{UInt8}
    [d.protocol_name[i] for i in 1:d.name_len]
end

protocol_name(p::Pattern) = String(protocol_name_bytes(descriptor(p)))

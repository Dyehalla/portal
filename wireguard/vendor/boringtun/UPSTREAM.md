# BoringTun tunnel core

This directory contains the WireGuard tunnel core from Cloudflare BoringTun
0.7.1, downloaded from the `boringtun` crate on crates.io. Upstream source
headers and the BSD 3-Clause license are retained. The standalone crate keeps
only `Tunn` and its protocol dependencies: handshake, sessions, timers, packet
parsing and the device-level rate limiter. BoringTun's OS device backends, FFI,
JNI and serialization modules are omitted.

The local changes in `src/noise/` add a typed ingress boundary and expose
bounded transmit-queue saturation to the embedding device:

- `Tunn::parse_packet` returns parsed fields together with the source datagram.
- `RateLimiter::prepare_packet` validates MAC/cookie state without parsing the
  datagram again and returns an opaque `PreparedPacket`.
- `Tunn::handle_prepared_packet` consumes that value while retaining BoringTun's
  handshake, session, AEAD and replay checks.
- `Tunn::decapsulate` remains available and uses the same path internally.
- `Tunn::encapsulate` reports `PacketQueueFull` when its bounded pre-handshake
  queue is full, so the embedding device can account for the rejected packet.

No WireGuard cryptography or handshake implementation was added to `portal`.

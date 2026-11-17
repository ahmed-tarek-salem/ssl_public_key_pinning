# ssl_public_key_pinning example

A runnable Flutter app demonstrating the core ssl_public_key_pinning API:

- probe a host's live SPKI pin (`fetchPinOf`)
- a pinned request that succeeds (correct pin, checked during the handshake)
- a pinned request that fails closed (wrong pin, nothing is ever sent)
- an unpinned host refused by the raw pinned client (fail-closed)

For multi-host routing, where unpinned hosts pass through normal CA
validation, use the `ssl_public_key_pinning_dio` or
`ssl_public_key_pinning_http` bindings.

Run it with `flutter run` from this directory.

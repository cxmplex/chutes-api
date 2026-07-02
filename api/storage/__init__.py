"""ChuteFS storage network: the validator-as-tracker control plane.

The validator never sees ChuteFS plaintext. It coordinates the decentralized storage network:
  - a content/replica registry (which attested storage TD holds which model repo@rev / object),
  - an attested storage-peer directory + per-peer attested-cert authority (so peers can mutually
    verify each other for the chute<->storage / storage<->storage mutually-attested TLS),
  - confidential per-user volume metadata + quotas + byte accounting,
  - per-volume application-layer key custody (released only to attested storage TDs holding a replica).
"""

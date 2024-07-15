OQS-OpenSSH snapshot 2024-08
============================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**OQS-OpenSSH** is an integration of liboqs into (a fork of) OpenSSH.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

Release notes
=============

This is the 2024-08 snapshot release of OQS-OpenSSH, released on August 30, 2024. This release is intended to be used with liboqs version 0.10.1.

What's New
----------

This is the eighth snapshot release of the OQS fork of OpenSSH.  It is based on OpenSSH 9.7 portable 1.

- Updated fork to track upstream OpenSSH 9.7.
- Update algorithm list in line with `liboqs` v0.10.1.
  + Introduces generic support for ML-KEM, ML-DSA, SNTRUP, BIKEr4, MAYO, and Falcon (Padded).
- Added support for x25519 hybrid key exchange algorithms.
  + Working interop support for `x25519-kyber-512r3-sha256-d00@amazon.com` key exchange.
  + Working interop support for `sntrup761x25519-sha512@openssh.com` key exchange.
- Support for all ML-KEM based hybrid key exchanges in https://datatracker.ietf.org/doc/draft-kampanakis-curdle-ssh-pq-ke/
  + `mlkem768nistp256-sha256`, `mlkem1024nistp384-sha384`, `mlkem768x25519-sha256`
- Migrated from CircleCI to Github Actions.

---

Detailed changelog
------------------

**Full Changelog**: https://github.com/open-quantum-safe/openssh/compare/OQS-v8...b89166ed6ff4eb9af7cbc5dc5c82049ebda388df
**Full Changelog (Omitting upstream merge): https://github.com/open-quantum-safe/openssh/compare/ac7c26b9e042fae7816eecaba9904e63bb706d12...b89166ed6ff4eb9af7cbc5dc5c82049ebda388df

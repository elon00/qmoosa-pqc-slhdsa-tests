# @qmoosa/pqc-slhdsa-tests

[![CI Gate](https://github.com/elon00/qmoosa-pqc-slhdsa-tests/actions/workflows/ci.yml/badge.svg)](https://github.com/elon00/qmoosa-pqc-slhdsa-tests/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> QMOOSA Post-Quantum Cryptography Suite — NIST FIPS 205 SLH-DSA Multi-Repo Reality Gates & Invariant CI.

## Overview

`@qmoosa/pqc-slhdsa-tests` serves as the reality gate for Batch 13 in Domain 2 of the QMOOSA-1000 portfolio. It validates supply-chain archive integrity, git commit provenance, hermetic packaging, cross-component integration, and a comprehensive adversarial negative control suite.

## Verification Tiers

1. **Gate 1: Archive Integrity Verification:** Cryptographic SHA-256 validation of packaged npm tarballs against `integrity-manifest.json`.
2. **Gate 2: Source Provenance Verification:** Git ancestry verification ensuring pinned commits exist in upstream history.
3. **Gate 3: Current-HEAD Alignment Gate:** Direct verification that sibling local repositories are strictly aligned with manifest commit hashes.
4. **Integration Test Suite:** Cross-repository end-to-end execution of Web4 transaction envelope lifecycles across multiple parameter sets (`SLH-DSA-SHA2-128s`, `SLH-DSA-SHA2-128f`, `SLH-DSA-SHAKE-128s`).
5. **Adversarial Negative Control Suite:** 14 independent negative controls verifying immediate rejection of forged signatures, tampered payloads, cross-chain replays, invalid seeds, and timing attacks.

## Execution

```bash
npm run verify:archive
npm run verify:source
npm run verify:current-head
npm run test:integration
npm run test:negative
npm run lint
```

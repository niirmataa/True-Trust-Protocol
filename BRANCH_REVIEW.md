# Branch Review: work Branch Overview

## Purpose
This document summarizes the current contents of the `work` branch so reviewers can quickly locate major capabilities and supporting documentation without needing to traverse the codebase manually.

## High-Level Capabilities
- Post-quantum focus with Falcon-512 signatures, Kyber-768 KEM, KMAC256 hashing, RandomX PoW, and STARK/Winterfell proofs highlighted in the top-level README.
- Deterministic PRO consensus uses weighted trust, quality, and stake factors with supporting Golden Trio quality scoring.
- Nodes expose multiple roles and utilities via the `tt_node` binary, including validator/full node modes, genesis initialization, consensus demos, crypto benchmarks, and feature self-tests.

## Key Entry Points and Modules
- **Node CLI**: `tt_node/src/main.rs` defines the `tt_node` entrypoint, command-line interface, and runtime wiring for validator/full node startup and operational commands.
- **Consensus Logic**: `tt_node/src/consensus_pro.rs` holds deterministic PRO consensus mechanics, while `tt_node/src/consensus_weights.rs` and `tt_node/src/golden_trio.rs` cover weighted scoring and validator quality components.
- **Cryptography**: Core PQ primitives reside under `tt_node/src/crypto/`, `tt_node/src/falcon_sigs.rs`, and `tt_node/src/kyber_kem.rs`, with additional security routines in `tt_node/src/stark_security.rs` and `tt_node/src/stark_full.rs` for zero-knowledge/STARK handling.
- **Networking**: Secure P2P transport and peer management live in `tt_node/src/p2p/`, aligning with the README’s emphasis on post-quantum-secure communication.
- **Wallet Support**: The optional wallet feature is gated behind the `wallet` Cargo feature and defined in `tt_node/src/wallet/` when enabled.

## Documentation and Guides
- **README.md**: High-level feature list, architecture overview, quick start, and project structure.
- **ADVANCED_NODE_README.md** and **WALLET_USAGE.md**: Deeper operational guidance for node and wallet workflows.
- **MINING_GUIDE.md** and **FINAL_SETUP.md**: Step-by-step mining and environment setup references.
- **SYSTEM_OVERVIEW.md**, **PROJECT_STATUS.md**, and **PQ_STATUS.md**: Current-state summaries and post-quantum readiness notes.

## Suggested Next Review Steps
- Validate that P2P Kyber handshakes, consensus weight calculations, and STARK verification paths have dedicated integration tests in `tt_node/tests/`.
- Exercise the CLI workflows (`validator`, `full-node`, `init-genesis`, `benchmark`, `test-all`) to confirm flags align with documented behaviors.
- Cross-check documentation references against current module names to keep “bit-for-bit” accuracy as the branch evolves.

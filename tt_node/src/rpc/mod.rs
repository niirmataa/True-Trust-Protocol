//! Secure PQ-aware RPC module
//!
//! Exposes node status, consensus monitoring, and transaction submission
//! over a Post-Quantum secure channel using the P2P protocol.

pub mod rpc_server;
pub mod rpc_secure;

pub use rpc_server::RpcServer;
pub use rpc_secure::SecureRpcServer;

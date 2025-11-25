#![forbid(unsafe_code)]

// Stary/nowszy kod z SecureRpcServer / SecureRpcClient
pub mod rpc_secure;

// Re-exporty, żeby można było pisać crate::rpc::{...}
pub use rpc_secure::{
    SecureRpcServer,
    SecureRpcClient,
    RpcRequest,
    RpcResponse,
};
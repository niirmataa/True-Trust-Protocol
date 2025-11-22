#![forbid(unsafe_code)]

//! Basic HTTP RPC module (INSECURE - use for localhost only!)
//!
//! ⚠️  WARNING: This uses unencrypted HTTP and should ONLY be used for:
//! - Local development
//! - Localhost connections
//! - Trusted private networks
//!
//! For production, use SecureRpcServer with PQ transport!

use anyhow::{anyhow, Result};
use hex;
use hyper::body::to_bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::falcon_sigs::{falcon_pk_from_bytes, FalconPublicKey};
use crate::node_core::NodeCore;
use crate::node_id::NodeId;

/// RPC server with access to core services (HTTP - INSECURE).
pub struct RpcServer {
    address: SocketAddr,
    node_id: NodeId,
    is_validator: bool,
    node: Arc<NodeCore>,
}

impl RpcServer {
    pub fn new(
        rpc_port: u16,
        node_id: NodeId,
        is_validator: bool,
        node: Arc<NodeCore>,
    ) -> Self {
        let address = SocketAddr::from(([127, 0, 0, 1], rpc_port)); // Localhost only!
        Self {
            address,
            node_id,
            is_validator,
            node,
        }
    }

    /// Start RPC server (HTTP - INSECURE).
    pub async fn start(self) -> Result<()> {
        let ctx = Arc::new(self);
        let server_addr = ctx.address;
        let make_svc = make_service_fn(move |_| {
            let ctx = Arc::clone(&ctx);
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let ctx = Arc::clone(&ctx);
                    async move { ctx.handle(req).await }
                }))
            }
        });

        println!("⚠️  INSECURE HTTP RPC on http://{}", server_addr);
        println!("⚠️  USE ONLY FOR LOCALHOST! For production use SecureRpcServer");
        let server = Server::bind(&server_addr).serve(make_svc);
        server.await.map_err(|e| anyhow!("RPC server error: {e}"))
    }

    async fn handle(self: &Arc<Self>, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/status") => self.handle_status().await,
            (&Method::GET, "/chain") => self.handle_chain().await,
            (&Method::GET, "/peers") => self.handle_peers().await,
            (&Method::POST, "/tx") => self.handle_tx(req).await,
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap()),
        }
    }

    async fn handle_status(&self) -> Result<Response<Body>, hyper::Error> {
        #[derive(Serialize)]
        struct Status {
            node_id: String,
            is_validator: bool,
            height: u64,
        }

        let height = self.node.get_chain_height().await;
        let status = Status {
            node_id: hex::encode(self.node_id),
            is_validator: self.is_validator,
            height,
        };
        json_response(&status)
    }

    async fn handle_chain(&self) -> Result<Response<Body>, hyper::Error> {
        #[derive(Serialize)]
        struct ChainInfo {
            height: u64,
            best_block_hash: String,
        }

        let height = self.node.get_chain_height().await;
        let best = self.node.get_best_block_hash().await;

        json_response(&ChainInfo {
            height,
            best_block_hash: hex::encode(best),
        })
    }

    async fn handle_peers(&self) -> Result<Response<Body>, hyper::Error> {
        let count = self.node.get_peer_count().await;

        #[derive(Serialize)]
        struct PeerInfo {
            count: usize,
        }

        json_response(&PeerInfo { count })
    }

    async fn handle_tx(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let bytes = to_bytes(req.into_body()).await?;
        let tx_hex: String = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("Invalid JSON: {e}")))
                    .unwrap())
            }
        };

        let tx_bytes = match hex::decode(&tx_hex) {
            Ok(b) => b,
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Invalid hex"))
                    .unwrap())
            }
        };

        // Submit to mempool
        match self.node.submit_transaction(&tx_bytes).await {
            Ok(tx_id) => {
                #[derive(Serialize)]
                struct TxResponse {
                    tx_id: String,
                    accepted: bool,
                }

                json_response(&TxResponse {
                    tx_id: hex::encode(tx_id),
                    accepted: true,
                })
            }
            Err(e) => Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("TX rejected: {e}")))
                .unwrap()),
        }
    }
}

fn json_response<T: Serialize>(value: &T) -> Result<Response<Body>, hyper::Error> {
    let body = serde_json::to_vec_pretty(value).unwrap_or_default();
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap())
}

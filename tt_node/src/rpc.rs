#![forbid(unsafe_code)]

//! Advanced RPC module exposing PQ-aware status, consensus monitoring, and tx submission.

use anyhow::{anyhow, Result};
use hex;
use hyper::body::to_bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::falcon_sigs::{falcon_pk_from_bytes, FalconPublicKey};
use crate::monitoring::{MonitoringService, NodeStatus};
use crate::node_core::NodeCore;
use crate::node_id::NodeId;
use crate::transaction::Transaction;

/// RPC server with access to core services.
pub struct RpcServer {
    address: SocketAddr,
    node_id: NodeId,
    is_validator: bool,
    node: Arc<NodeCore>,
    monitoring: Arc<MonitoringService>,
}

impl RpcServer {
    pub fn new(
        rpc_port: u16,
        node_id: NodeId,
        is_validator: bool,
        node: Arc<NodeCore>,
        monitoring: Arc<MonitoringService>,
    ) -> Self {
        let address = SocketAddr::from(([0, 0, 0, 0], rpc_port));
        Self {
            address,
            node_id,
            is_validator,
            node,
            monitoring,
        }
    }

    /// Start RPC server.
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

        println!("🔌 RPC listening on http://{}", server_addr);
        let server = Server::bind(&server_addr).serve(make_svc);
        server.await.map_err(|e| anyhow!("RPC server error: {e}"))
    }

    async fn handle(self: &Arc<Self>, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/status") => self.handle_status().await,
            (&Method::GET, "/consensus") => self.handle_consensus().await,
            (&Method::GET, "/chain") => self.handle_chain().await,
            (&Method::GET, "/peers") => self.handle_peers().await,
            (&Method::GET, "/metrics") => self.handle_metrics().await,
            (&Method::POST, "/tx") => self.handle_tx(req).await,
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap()),
        }
    }

    async fn handle_status(&self) -> Result<Response<Body>, hyper::Error> {
        let chain = self.monitoring.chain_health().await;
        let consensus = self.monitoring.consensus_health().await;
        let p2p = self.monitoring.p2p_health().await;
        let txpool = self.monitoring.txpool_health().await;

        let status = NodeStatus::new(
            self.node_id,
            self.is_validator,
            chain,
            consensus,
            p2p,
            txpool,
        );
        json_response(&status)
    }

    async fn handle_consensus(&self) -> Result<Response<Body>, hyper::Error> {
        let consensus = self.monitoring.consensus_health().await;
        json_response(&consensus)
    }

    async fn handle_chain(&self) -> Result<Response<Body>, hyper::Error> {
        let chain = self.monitoring.chain_health().await;
        json_response(&chain)
    }

    async fn handle_peers(&self) -> Result<Response<Body>, hyper::Error> {
        let peers = self.monitoring.p2p_health().await;
        json_response(&peers)
    }

    async fn handle_metrics(&self) -> Result<Response<Body>, hyper::Error> {
        #[derive(Serialize)]
        struct MetricsBundle {
            chain: crate::monitoring::ChainHealth,
            consensus: crate::consensus_pro::ConsensusStats,
            p2p: crate::monitoring::P2PHealth,
            txpool: crate::monitoring::TxPoolHealth,
        }

        let metrics = MetricsBundle {
            chain: self.monitoring.chain_health().await,
            consensus: self.monitoring.consensus_health().await,
            p2p: self.monitoring.p2p_health().await,
            txpool: self.monitoring.txpool_health().await,
        };

        json_response(&metrics)
    }

    async fn handle_tx(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let bytes = to_bytes(req.into_body()).await?;
        let submit: SubmitTxRequest = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("Invalid JSON: {e}")))
                    .unwrap())
            }
        };

        // Verify signature if provided
        if let Some(pk_hex) = submit.falcon_public_key_hex.as_ref() {
            let pk_bytes = match hex::decode(pk_hex) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("Invalid Falcon public key hex"))
                        .unwrap())
                }
            };

            let pk: FalconPublicKey = match falcon_pk_from_bytes(&pk_bytes) {
                Ok(pk) => pk,
                Err(e) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(format!("Invalid Falcon key: {e}")))
                        .unwrap())
                }
            };

            if let Err(e) = submit.transaction.verify(&pk) {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("Signature verification failed: {e}")))
                    .unwrap());
            }
        }

        let tx_id = submit.transaction.id();

        {
            let mut pool = self.node.tx_pool.write().await;
            if let Err(e) = pool.add(submit.transaction) {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("Tx rejected: {e}")))
                    .unwrap());
            }
        }

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
}

#[derive(Debug, Deserialize)]
pub struct SubmitTxRequest {
    pub transaction: Transaction,
    pub falcon_public_key_hex: Option<String>,
}

fn json_response<T: Serialize>(value: &T) -> Result<Response<Body>, hyper::Error> {
    let body = serde_json::to_vec_pretty(value).unwrap_or_default();
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap())
}

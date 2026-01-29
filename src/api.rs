use axum::{
    extract::{State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use crate::engine::CoreEngine;

#[derive(Clone)]
pub struct AppState {
    #[allow(dead_code)]
    pub engine: Arc<Option<CoreEngine>>, // Placeholder for now, real implementation would manage multiple engines
    pub scan_status: Arc<Mutex<String>>,
}

#[derive(Deserialize)]
pub struct ScanRequest {
    pub target: String,
    #[allow(dead_code)]
    pub method: Option<String>,
    #[allow(dead_code)]
    pub concurrency: Option<usize>,
}

#[derive(Serialize)]
pub struct ScanResponse {
    pub id: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub status: String,
}

pub async fn start_api() {
    let state = AppState {
        engine: Arc::new(None),
        scan_status: Arc::new(Mutex::new("Idle".to_string())),
    };

    let app = Router::new()
        .route("/scan", post(start_scan))
        .route("/status", get(get_status))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("API listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn start_scan(
    State(state): State<AppState>,
    Json(payload): Json<ScanRequest>,
) -> Json<ScanResponse> {
    let mut status = state.scan_status.lock().unwrap();
    if *status == "Running" {
        return Json(ScanResponse {
            id: "error".to_string(),
            status: "Scan already running".to_string(),
        });
    }

    *status = "Running".to_string();
    let status_clone = state.scan_status.clone();
    let target = payload.target.clone();

    // Spawn dummy scan task (Integration with CoreEngine comes next)
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        let mut s = status_clone.lock().unwrap();
        *s = format!("Completed scan on {}", target);
    });

    Json(ScanResponse {
        id: "scan_123".to_string(), // Mock ID
        status: "Started".to_string(),
    })
}

async fn get_status(State(state): State<AppState>) -> Json<StatusResponse> {
    let status = state.scan_status.lock().unwrap();
    Json(StatusResponse {
        status: status.clone(),
    })
}

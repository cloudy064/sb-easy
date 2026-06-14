//! WebSocket proxy for the sing-box Clash API streaming endpoints
//! (`/traffic`, `/logs`, `/connections`, `/memory`).
//!
//! Browsers can't set an `Authorization` header on a WebSocket handshake, so
//! these routes authenticate via a `?token=<jwt>` query param (validated with
//! the same secret as normal API auth) and live in the public router group.
//! Once authorized the server opens a client WS to sing-box and forwards the
//! stream downstream.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as UpMessage;

use crate::util::encode_query_component;
use crate::AppState;

const STREAMS: [&str; 4] = ["traffic", "logs", "connections", "memory"];

pub fn router() -> Router<AppState> {
    Router::new().route("/ws/{kind}", get(ws_handler))
}

async fn ws_handler(
    State(state): State<AppState>,
    Path(kind): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Response {
    let authed = params
        .get("token")
        .map(|t| crate::auth::verify_token(t, &state.cfg.jwt_secret).is_ok())
        .unwrap_or(false);
    if !authed {
        return (axum::http::StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    if !STREAMS.contains(&kind.as_str()) {
        return (axum::http::StatusCode::NOT_FOUND, "unknown stream").into_response();
    }
    ws.on_upgrade(move |socket| proxy(socket, state, kind, params))
}

async fn proxy(mut client: WebSocket, state: AppState, kind: String, params: HashMap<String, String>) {
    // Per-host target over the WG intranet when `?host=<id>` is given, else local.
    let (base, secret) =
        crate::api::hosts::resolve_clash_target(&state, params.get("host").map(|s| s.as_str())).await;
    let ws_base = base
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);

    let mut qs: Vec<String> = Vec::new();
    if !secret.is_empty() {
        qs.push(format!("token={}", encode_query_component(&secret)));
    }
    if kind == "logs" {
        if let Some(level) = params.get("level") {
            qs.push(format!("level={}", encode_query_component(level)));
        }
    }
    let url = if qs.is_empty() {
        format!("{ws_base}/{kind}")
    } else {
        format!("{ws_base}/{kind}?{}", qs.join("&"))
    };

    let upstream = match connect_async(&url).await {
        Ok((s, _)) => s,
        Err(e) => {
            let _ = client
                .send(Message::Text(
                    format!("{{\"error\":\"upstream connect failed: {e}\"}}").into(),
                ))
                .await;
            return;
        }
    };
    let (_up_tx, mut up_rx) = upstream.split();

    // Read-only streams: forward upstream → browser; stop when either side closes.
    loop {
        tokio::select! {
            msg = up_rx.next() => match msg {
                Some(Ok(UpMessage::Text(t))) => {
                    if client.send(Message::Text(t.to_string().into())).await.is_err() { break; }
                }
                Some(Ok(UpMessage::Binary(b))) => {
                    if client.send(Message::Binary(b.to_vec().into())).await.is_err() { break; }
                }
                Some(Ok(UpMessage::Ping(p))) => {
                    let _ = client.send(Message::Ping(p.to_vec().into())).await;
                }
                Some(Ok(_)) => {}
                _ => break,
            },
            cmsg = client.recv() => match cmsg {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
        }
    }
}

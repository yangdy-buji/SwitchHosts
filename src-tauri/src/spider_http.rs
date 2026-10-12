//! Versioned browser transport for the native Spider engine.
use crate::{spider, storage::AppState};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter, Manager, Wry};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
static PAIRING: Mutex<PairingState> = Mutex::new(PairingState {
    pending: false,
    last: None,
});
fn error(code: StatusCode, message: impl ToString) -> Response {
    (code, Json(json!({"message":message.to_string()}))).into_response()
}
fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    if headers.get_all(name).iter().count() != 1 {
        return "";
    }
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}
pub fn router(app: AppHandle<Wry>) -> Router {
    Router::new()
        .route("/api/v1/spider/status", get(read_status).options(preflight))
        .route("/api/v1/spider/pair", post(pair).options(preflight))
        .route(
            "/api/v1/spider/environment",
            put(environment).options(preflight),
        )
        .route(
            "/api/v1/spider/profiles",
            put(profiles)
                .options(preflight)
                .layer(DefaultBodyLimit::max(810 * 1024)),
        )
        .layer(DefaultBodyLimit::max(270 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app)
}
async fn preflight() -> StatusCode {
    StatusCode::NO_CONTENT
}
async fn guard(State(app): State<AppHandle<Wry>>, request: Request, next: Next) -> Response {
    let Some(ConnectInfo(peer)) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied()
    else {
        return error(StatusCode::FORBIDDEN, "Missing loopback peer");
    };
    let headers = request.headers();
    let pairing = request.uri().path() == "/api/v1/spider/pair" && request.method() == Method::POST;
    let options = request.method() == Method::OPTIONS;
    if let Err(e) = spider::authorize(
        peer,
        header(headers, "host"),
        header(headers, "origin"),
        None,
        None,
        true,
    ) {
        return error(StatusCode::FORBIDDEN, e);
    }
    let outcome = if !pairing && !options {
        let state = app.state::<AppState>();
        match read_token(&state) {
            Ok(token) => spider::authorize(
                peer,
                header(headers, "host"),
                header(headers, "origin"),
                Some(header(headers, "authorization")),
                token.as_deref(),
                false,
            )
            .map_err(|e| error(StatusCode::UNAUTHORIZED, e)),
            Err(e) => Err(error(StatusCode::SERVICE_UNAVAILABLE, e)),
        }
    } else {
        Ok(())
    };
    let mut response = match outcome {
        Ok(()) => next.run(request).await,
        Err(response) => response,
    };
    response.headers_mut().insert(
        "access-control-allow-origin",
        HeaderValue::from_static(spider::ORIGIN),
    );
    response
        .headers_mut()
        .insert("vary", HeaderValue::from_static("Origin"));
    response.headers_mut().insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET, POST, PUT, OPTIONS"),
    );
    response.headers_mut().insert(
        "access-control-allow-headers",
        HeaderValue::from_static("Authorization, Content-Type"),
    );
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    // Supports browsers using the PNA preflight in addition to current LNA permission.
    response.headers_mut().insert(
        "access-control-allow-private-network",
        HeaderValue::from_static("true"),
    );
    response
}
fn read_token(state: &AppState) -> Result<Option<String>, String> {
    let path = state.paths.root.join("internal/spider-token");
    match std::fs::read_to_string(path) {
        Ok(token) if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Ok(Some(token))
        }
        Ok(_) => Err("Corrupt pairing token; repair local bridge storage".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn persist_token(state: &AppState) -> Result<String, String> {
    if let Some(token) = read_token(state)? {
        return Ok(token);
    }
    use std::io::Write;
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| e.to_string())?;
    let token = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let path = state.paths.root.join("internal/spider-token");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(|e| e.to_string())?;
    if let Err(e) = file
        .write_all(token.as_bytes())
        .and_then(|_| file.sync_all())
    {
        let _ = std::fs::remove_file(path);
        return Err(e.to_string());
    }
    Ok(token)
}
async fn pair(State(app): State<AppHandle<Wry>>) -> Response {
    {
        let mut guard = PAIRING.lock().unwrap();
        if !guard.begin(Instant::now()) {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "Pairing already pending or requested recently; wait 30 seconds",
            );
        }
    }
    match tauri::async_runtime::spawn_blocking(move||{
        struct Reset;
        impl Drop for Reset {fn drop(&mut self){if let Ok(mut state)=PAIRING.lock(){state.pending=false;}}}
        let _reset=Reset;
        let state=app.state::<AppState>();state.require_data_dir_usable().map_err(|e|e.to_string())?;
        // blocking_show runs on this worker; plugin schedules the native window.
        let approved=app.dialog().message("允许 https://spider.yangdy.com 切换此电脑的 Spider 运行环境 hosts？仅管理 Spider 环境分组。请仅在你刚刚点击连接时允许。").title("连接 Spider 与 SwitchHosts").buttons(MessageDialogButtons::OkCancel).blocking_show();
        if !approved{return Err("Pairing cancelled".to_string());}
        let _guard=state.store_lock.lock().map_err(|_|"Storage lock poisoned")?;
        persist_token(&state)
    }).await {Ok(Ok(token))=>Json(json!({"apiVersion":1,"token":token})).into_response(),Ok(Err(e))=>error(StatusCode::FORBIDDEN,e),Err(e)=>error(StatusCode::INTERNAL_SERVER_ERROR,e)}
}
async fn read_status(State(app): State<AppHandle<Wry>>) -> Response {
    match tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        state.require_data_dir_usable().map_err(|e| e.to_string())?;
        let _apply = spider::APPLY_LOCK
            .lock()
            .map_err(|_| "Apply lock poisoned")?;
        let _store = state
            .store_lock
            .lock()
            .map_err(|_| "Storage lock poisoned")?;
        let hosts = crate::hosts_apply::write::system_hosts_path().map_err(|e| e.to_string())?;
        spider::status(&state.paths, &hosts)
    })
    .await
    {
        Ok(Ok(status)) => Json(status).into_response(),
        Ok(Err(e)) => error(StatusCode::SERVICE_UNAVAILABLE, e),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
async fn environment(
    State(app): State<AppHandle<Wry>>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Response {
    let body = match body {
        Ok(b) => b,
        Err(e) => return error(StatusCode::PAYLOAD_TOO_LARGE, e),
    };
    let request: spider::Environment = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    respond_change(app, Change::Environment(request)).await
}
async fn profiles(
    State(app): State<AppHandle<Wry>>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Response {
    let body = match body {
        Ok(b) => b,
        Err(e) => return error(StatusCode::PAYLOAD_TOO_LARGE, e),
    };
    let request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    respond_change(app, Change::Profiles(request)).await
}
pub(crate) enum Change {
    Environment(spider::Environment),
    Profiles(spider::Profiles),
    Toggle { id: String, on: bool },
}
pub(crate) async fn execute_change(
    app: AppHandle<Wry>,
    change: Change,
) -> Result<spider::Status, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        state.require_data_dir_usable().map_err(|e| e.to_string())?;
        let _apply = spider::APPLY_LOCK
            .lock()
            .map_err(|_| "Apply lock poisoned")?;
        let _store = state
            .store_lock
            .lock()
            .map_err(|_| "Storage lock poisoned")?;
        let hosts = crate::hosts_apply::write::system_hosts_path().map_err(|e| e.to_string())?;
        let limit = state
            .config
            .lock()
            .map_err(|_| "Config lock poisoned")?
            .history_limit as i32;
        let mut writer = |content: &str| {
            let outcome = crate::hosts_apply::write::apply_exact_to_system_hosts(content)
                .map_err(|e| e.to_string())?;
            if !outcome.unchanged {
                let path = state.paths.histories_dir.join("system-hosts.json");
                for (index, content) in [outcome.previous_content, outcome.new_content]
                    .into_iter()
                    .enumerate()
                {
                    let now = chrono::Utc::now().timestamp_millis();
                    let item = crate::hosts_apply::ApplyHistoryItem {
                        id: format!("spider-{now}-{index}"),
                        content,
                        add_time_ms: now,
                        label: Some("Spider environment".into()),
                    };
                    if let Err(e) = crate::hosts_apply::history::insert(&path, item, limit) {
                        log::warn!("Spider history failed: {e}");
                    }
                }
            }
            Ok(())
        };
        let status = match change {
            Change::Environment(request) => {
                spider::apply(&state.paths, &hosts, &request, &mut writer)
            }
            Change::Profiles(request) => {
                spider::sync_profiles(&state.paths, &hosts, &request, &mut writer)
            }
            Change::Toggle { id, on } => {
                spider::toggle_cached(&state.paths, &hosts, &id, on, &mut writer)
            }
        }?;
        if let Some((event, payload)) = profile_refresh_event(&status.mode) {
            let _ = app.emit(event, payload);
        }
        let _ = app.emit("system_hosts_updated", json!({"_args":[]}));
        let _ = app.emit("reload_list", json!({"_args":[]}));
        Ok::<_, String>(status)
    })
    .await
    .map_err(|e| e.to_string())?
}
fn profile_refresh_event(mode: &str) -> Option<(&'static str, serde_json::Value)> {
    spider::profile_refresh_id(mode)
        .map(|profile_id| ("hosts_refreshed_by_id", json!({"_args":[profile_id]})))
}
async fn respond_change(app: AppHandle<Wry>, change: Change) -> Response {
    match execute_change(app, change).await {
        Ok(status) => Json(status).into_response(),
        Err(e) => error(StatusCode::CONFLICT, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pairing_cannot_open_a_second_dialog_while_first_is_pending() {
        let mut state = PairingState::default();
        let now = Instant::now();
        assert!(state.begin(now));
        assert!(!state.begin(now + Duration::from_secs(90)));
        state.pending = false;
        assert!(state.begin(now + Duration::from_secs(90)));
    }
    #[test]
    fn header_guard_rejects_ambiguous_duplicate_origin() {
        let mut headers = HeaderMap::new();
        headers.append("origin", HeaderValue::from_static(spider::ORIGIN));
        headers.append("origin", HeaderValue::from_static("https://evil.test"));
        assert_eq!(header(&headers, "origin"), "");
    }

    #[test]
    fn profile_refresh_event_targets_the_editor_content_listener() {
        assert_eq!(
            profile_refresh_event("daily"),
            Some((
                "hosts_refreshed_by_id",
                json!({"_args":["spider-managed-environment-daily"]})
            ))
        );
        assert_eq!(profile_refresh_event("system"), None);
    }
}
#[derive(Default)]
struct PairingState {
    pending: bool,
    last: Option<Instant>,
}
impl PairingState {
    fn begin(&mut self, now: Instant) -> bool {
        if self.pending
            || self
                .last
                .is_some_and(|at| now.duration_since(at) < Duration::from_secs(30))
        {
            return false;
        }
        self.pending = true;
        self.last = Some(now);
        true
    }
}

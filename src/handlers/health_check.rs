use axum::{http::StatusCode, response::IntoResponse};

pub async fn healthcheck() -> impl IntoResponse {
    StatusCode::OK
}

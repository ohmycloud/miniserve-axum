use std::{str::FromStr, usize};

use axum::{
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tower::Service;

fn generate_error_page(status: StatusCode, error_message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error {}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .error-container {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .error-code {{
            font-size: 48px;
            font-weight: bold;
            color: #e74c3c;
            margin-bottom: 10px;
        }}
        .error-title {{
            font-size: 24px;
            color: #333;
            margin-bottom: 20px;
        }}
        .error-message {{
            color: #666;
            line-height: 1.5;
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            border-left: 4px solid #e74c3c;
        }}
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-code">{}</div>
        <div class="error-title">{}</div>
        <div class="error-message">{}</div>
    </div>
</body>
</html>"#,
        status.as_u16(),
        status.as_u16(),
        status.canonical_reason().unwrap_or("Error"),
        html_escape(error_message)
    )
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub async fn error_page_middleware(req: Request, mut next: Next) -> Response {
    let uri_path = req.uri().path().to_string();
    let res = next.call(req).await.unwrap();
    if (res.status().is_client_error() || res.status().is_server_error())
        && uri_path != "/upload"
        && res
            .headers()
            .get(header::CONTENT_TYPE)
            .map(AsRef::as_ref)
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| mime::Mime::from_str(s).ok())
            .as_ref()
            .map(mime::Mime::essence_str)
            == Some(mime::TEXT_PLAIN.as_ref())
    {
        let status = res.status();
        let (_parts, body) = res.into_parts();
        let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to response body")
                    .into_response();
            }
        };

        let error_message = String::from_utf8_lossy(&body_bytes);
        let html_content = generate_error_page(status, &error_message);
        let mut response = html_content.into_response();
        *response.status_mut() = status;

        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );

        response
    } else {
        res
    }
}

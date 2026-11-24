use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use flamejob_api::Problem;

#[derive(Debug)]
pub enum AppError {
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    BadRequest(String),
    /// Quota/rate backpressure (e.g. a group's max concurrent submitted jobs).
    TooManyRequests(String),
    Internal(String),
}

impl AppError {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "unauthorized", m.clone()),
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, "forbidden", m.clone()),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m.clone()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m.clone()),
            AppError::TooManyRequests(m) => (
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                m.clone(),
            ),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", m.clone()),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, slug, detail) = self.parts();
        let body = Problem {
            type_uri: format!("https://flamejob/errors/{slug}"),
            title: slug.to_string(),
            status: code.as_u16(),
            detail: Some(detail),
        };
        (code, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}

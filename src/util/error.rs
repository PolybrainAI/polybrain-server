/*

Error definitions

Copyright Polybrain 2024

*/

use log::error;
use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use serde::Serialize;
use std::io::Cursor;
use uuid::Uuid;

// Creates a random traceid and sends it to the STDOUT
pub fn gen_trace() -> String {
    let trace_id = Uuid::new_v4().to_string();
    error!("TRACE_ID: {trace_id}");
    trace_id
}

pub trait PolybrainError {
    fn to_json(&self) -> String
    where
        Self: Serialize,
    {
        serde_json::to_string_pretty(&self).expect("Failed to serialize error type")
    }
}

#[derive(Serialize, Debug)]
pub struct AuthorizationError {
    pub message: String,
    pub trace: String,
    pub error_type: String,
}
impl AuthorizationError {
    pub fn new(message: &str) -> AuthorizationError {
        AuthorizationError {
            message: message.to_string(),
            trace: gen_trace(),
            error_type: "AuthorizationError".to_owned(),
        }
    }
}
impl PolybrainError for AuthorizationError {}

#[rocket::async_trait]
impl<'r> Responder<'r, 'static> for AuthorizationError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let json = self.to_json();
        Response::build()
            .header(ContentType::JSON)
            .status(Status::Forbidden)
            .sized_body(json.len(), Cursor::new(json))
            .ok()
    }
}

#[derive(Serialize, Debug)]
pub struct AuthenticationError {
    pub message: String,
    pub trace: String,
    pub error_type: String,
}
impl AuthenticationError {
    pub fn _new(message: &str) -> AuthenticationError {
        AuthenticationError {
            message: message.to_string(),
            trace: gen_trace(),
            error_type: "AuthenticationError".to_owned(),
        }
    }
}
impl PolybrainError for AuthenticationError {}

#[rocket::async_trait]
impl<'r> Responder<'r, 'static> for AuthenticationError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let json = self.to_json();
        Response::build()
            .header(ContentType::JSON)
            .status(Status::Unauthorized)
            .sized_body(json.len(), Cursor::new(json))
            .ok()
    }
}

#[derive(Serialize, Debug)]
pub struct InternalError {
    pub message: String,
    pub operation: String,
    pub trace: String,
    pub error_type: String,
}
impl InternalError {
    pub fn _new(message: &str, operation: &str) -> InternalError {
        InternalError {
            message: message.to_string(),
            operation: operation.to_string(),
            trace: gen_trace(),
            error_type: "InternalError".to_owned(),
        }
    }
}
impl PolybrainError for InternalError {}

#[rocket::async_trait]
impl<'r> Responder<'r, 'static> for InternalError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let json = self.to_json();
        Response::build()
            .header(ContentType::JSON)
            .status(Status::InternalServerError)
            .sized_body(json.len(), Cursor::new(json))
            .ok()
    }
}

#[derive(Serialize, Debug)]
pub struct BadRequest {
    pub message: String,
    pub trace: String,
    pub error_type: String,
}
impl BadRequest {
    pub fn new(message: &str) -> BadRequest {
        BadRequest {
            message: message.to_string(),
            trace: gen_trace(),
            error_type: "BadRequest".to_owned(),
        }
    }
}
impl PolybrainError for BadRequest {}

#[rocket::async_trait]
impl<'r> Responder<'r, 'static> for BadRequest {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let json = self.to_json();
        Response::build()
            .header(ContentType::JSON)
            .status(Status::Unauthorized)
            .sized_body(json.len(), Cursor::new(json))
            .ok()
    }
}

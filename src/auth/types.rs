/*

Auth Type Definitions
Different Auth0 and Polybrain response schemas are defined here

Copyright Polybrain 2024

*/

use rocket::http::ContentType;
use rocket::response::Redirect;
use rocket::response::{self, Responder};
use rocket::Request;
use rocket::Response;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

#[derive(Serialize)]
pub struct TokenExchangeRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub code: String,
    pub redirect_uri: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub scope: String,
    pub expires_in: i64,
    pub token_type: String,
}

#[allow(clippy::large_enum_variant)]
pub enum TextOrRedirect {
    Text(String),
    Redirect(Redirect),
}

// Implement the Responder trait for TextOrRedirect
impl<'r> Responder<'r, 'static> for TextOrRedirect {
    fn respond_to(self, req: &Request<'_>) -> response::Result<'static> {
        match self {
            TextOrRedirect::Text(text) => Response::build()
                .header(ContentType::Plain)
                .sized_body(text.len(), Cursor::new(text))
                .ok(),
            TextOrRedirect::Redirect(redirect) => redirect.respond_to(req),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserPreliminaryInfo {
    pub sub: String,
    pub given_name: Option<String>,
    pub username: Option<String>,
    pub family_name: Option<String>,
    pub nickname: Option<String>,
    pub name: String,
    pub picture: Option<String>,
    pub email: String,
    pub locale: Option<String>,
    pub updated_at: Option<String>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserInfo {
    pub created_at: String,
    pub email: String,
    pub name: String,
    pub user_id: String,
    pub username: Option<String>,
    pub last_ip: String,
    pub last_login: String,
    pub given_name: Option<String>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Auth0Error {
    error: String,
    error_description: String,
    error_uri: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Auth0Response {
    UserInfo(UserInfo),
    Auth0Error(Auth0Error),
}

#[derive(Debug)]
pub struct Auth0Config {
    pub domain: String,
    pub client_id: String,
    pub callback: String,
    pub secret: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Auth0ManagementTokenSave {
    pub token: String,
    pub expires: usize,
}
#[derive(Debug, Deserialize)]
pub struct Auth0ManagementTokenResponse {
    pub access_token: String,
    pub expires_in: usize,
}

#[derive(Debug, Serialize)]
pub struct Auth0ManagementTokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
}

impl Auth0Config {
    pub fn load() -> Auth0Config {
        Auth0Config {
            domain: std::env::var("AUTH0_DOMAIN").expect("AUTH0_DOMAIN must be set"),
            client_id: std::env::var("AUTH0_CLIENT_ID").expect("AUTH0_CLIENT_ID must be set"),
            callback: std::env::var("AUTH0_CALLBACK").expect("AUTH0_CALLBACK must be set"),
            secret: std::env::var("AUTH0_CLIENT_SECRET").expect("AUTH0_CLIENT_SECRET must be set"),
        }
    }
}

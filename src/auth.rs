use std::collections::HashMap;

use crate::error::gen_trace;

use super::error::{AuthenticationError, AuthorizationError};
use reqwest;
use rocket::http::CookieJar;
use rocket::response::Redirect;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct TokenExchangeRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct TokenExchangeResponse {
    access_token: String,
    scope: String,
    expires_in: i64,
    token_type: String,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
pub struct UserInfo {
    pub sub: String,
    pub given_name: String,
    pub family_name: Option<String>,
    pub nickname: String,
    pub name: String,
    pub picture: Option<String>,
    pub email: String,
    pub locale: Option<String>,
    pub updated_at: String,
}

pub struct Auth0Config {
    pub domain: String,
    pub client_id: String,
    pub callback: String,
    pub secret: String,
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

/// The URL to to Auth0's /authorize endpoint
fn create_authorize_redirect_url(auth0_config: Auth0Config) -> String {
    format!(
        "https://{AUTH0_DOMAIN}/authorize?response_type=code&client_id={AUTH0_CLIENT_ID}&redirect_uri={AUTH0_CALLBACK}&scope=openid%20profile%20email",
        AUTH0_DOMAIN = auth0_config.domain,
        AUTH0_CLIENT_ID = auth0_config.client_id,
        AUTH0_CALLBACK = auth0_config.callback,
    )
}

/// Gets Auth0 stored user data
pub async fn get_user_data(user_token: &str) -> UserInfo{
    let client = reqwest::Client::new();

    let user_info_url = format!("https://{}/userinfo", Auth0Config::load().domain);

    let mut headers = HashMap::new();
    headers.insert("Authorization", format!("Bearer {user_token}"));

    println!("Getting user data with headers: {:?}", headers);

    let user_info: UserInfo = client
        .get(user_info_url)
        .header("Authorization", format!("Bearer {user_token}"))
        .send()
        .await
        .inspect_err(|err| eprintln!("Failed to fetch user info from Auth0: {err}"))
        .unwrap()
        .json()
        .await
        .inspect_err(|err| eprintln!("Failed to deserialize user info from Auth0: {err}"))
        .unwrap();

    user_info
}

/// Redirects the user to the Auth0 login page
#[get("/auth0/login", rank=0)]
pub async fn auth0_login() -> Redirect {
    println!("Redirecting to Auth0 login");
    let auth0_config = Auth0Config::load();
    let redirect_url = create_authorize_redirect_url(auth0_config);

    Redirect::to(redirect_url)
}

/// Auth0 redirects here when it's ready. We exchange temp code for a JWT
#[get("/auth0/callback?<code>", rank=0)]
pub async fn auth0_callback(cookies: &CookieJar<'_>, code: &str) -> Redirect {
    println!("Got auth0 callback");

    let auth0_config = Auth0Config::load();

    let token_exchange_url = format!("https://{}/oauth/token", auth0_config.domain);

    println!("Exchanging token at: {}", token_exchange_url);
    let token_body = TokenExchangeRequest {
        grant_type: "authorization_code".to_owned(),
        client_id: auth0_config.client_id,
        client_secret: auth0_config.secret,
        code: code.to_owned(),
        redirect_uri: auth0_config.callback,
    };

    let client = reqwest::Client::new();
    let token_response: TokenExchangeResponse = client
        .post(token_exchange_url)
        .json(&token_body)
        .send()
        .await
        .inspect_err(|err| eprintln!("error on token change (outer): {err}"))
        .unwrap()
        .json()
        .await
        .inspect_err(|err| eprintln!("error on token change (inner): {err}"))
        .unwrap();

    println!("Adding token to cookie jar");
    cookies.add(("polybrain-session", token_response.access_token));

    let user_page = format!(
        "{}/auth0/user-data",
        std::env::var("API_BASE").expect("API_BASE must be set.")
    );
    println!("Redirecting to {user_page}");
    Redirect::to(user_page)
}

#[get("/auth0/user-data", rank=0)]
pub async fn auth0_user_data(cookies: &CookieJar<'_>) -> Result<String, AuthorizationError> {
    if let Some(token) = cookies.get("polybrain-session") {
        let user_info = get_user_data(token.value()).await;
        Ok(serde_json::to_string_pretty(&user_info).unwrap())
    } else {
        Err(AuthorizationError::new("You must be logged in to view user data"))
    }
}

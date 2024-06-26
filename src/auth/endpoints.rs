/*

Exposed endpoints for Polybrain authentication
Interfaces with Auth utilities (./util.rs) to complete user authentication

Copyright Polybrain 2024

*/

use log::{error};
use reqwest;
use rocket::http::CookieJar;
use rocket::response::Redirect;

use crate::auth::types::{
    Auth0Config, TextOrRedirect, TokenExchangeRequest, TokenExchangeResponse,
};
use crate::auth::util::{create_authorize_redirect_url, get_user_data};
use crate::util::error::AuthorizationError;

/// Redirects the user to the Auth0 logout page
#[get("/auth0/logout", rank = 0)]
pub async fn auth0_logout(cookies: &CookieJar<'_>) -> Redirect {
    println!("[auth0/logout]: removing user token");
    if let Some(cookie) = cookies.get("polybrain-session") {
        cookies.remove(cookie.to_owned());
    };

    println!("[auth0/logout]: redirecting to Auth0 logout");
    let auth0_config = Auth0Config::load();
    let redirect_url = format!(
        "https://{AUTH0_DOMAIN}/v2/logout?client_id={AUTH0_CLIENT_ID}&returnTo={LOGOUT_URL}",
        AUTH0_DOMAIN = auth0_config.domain,
        AUTH0_CLIENT_ID = auth0_config.client_id,
        LOGOUT_URL = std::env::var("API_BASE").expect("API_BASE must be set.")
    );

    Redirect::to(redirect_url)
}

/// Auth0 redirects here when it's ready. We exchange temp code for a JWT
#[get("/auth0/callback?<code>", rank = 0)]
pub async fn auth0_callback(cookies: &CookieJar<'_>, code: &str) -> Redirect {
    let auth0_config = Auth0Config::load();
    let token_exchange_url = format!("https://{}/oauth/token", auth0_config.domain);

    println!(
        "[auth0/callback]: fetching token at: {}",
        token_exchange_url
    );
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
        .inspect_err(|err| error!("error on token change (outer): {err}"))
        .unwrap()
        .json()
        .await
        .inspect_err(|err| error!("error on token change (inner): {err}"))
        .unwrap();

    println!("[auth0/callback]: adding token to user's cookie jar");
    cookies.add(("polybrain-session", token_response.access_token));

    let user_page = format!(
        "{}/portal",
        std::env::var("API_BASE").expect("API_BASE must be set.")
    );
    println!("[auth0/callback]: redirecting to {user_page}");
    Redirect::to(user_page)
}

/// Gets basic information about the current user
#[get("/auth0/user-data", rank = 0)]
pub async fn auth0_user_data(
    cookies: &CookieJar<'_>,
) -> Result<TextOrRedirect, AuthorizationError> {
    if let Some(token) = cookies.get("polybrain-session") {
        let user_info = get_user_data(token.value()).await;

        if let Ok(info) = &user_info {
            Ok(TextOrRedirect::Text(
                serde_json::to_string_pretty(info).unwrap(),
            ))
        } else {
            warn!("[auth0/user-data]: user has an invalid token. Logging out.");
            Ok(TextOrRedirect::Redirect(Redirect::to(format!(
                "{API_BASE}/auth0/logout",
                API_BASE = std::env::var("API_BASE").expect("API_BASE must be set.")
            ))))
        }
    } else {
        Err(AuthorizationError::new(
            "You must be logged in to view user data",
        ))
    }
}

/// Redirects the user to the Auth0 login page
#[get("/auth0/login", rank = 0)]
pub async fn auth0_login() -> Redirect {
    println!("[auth0/login] redirecting to Auth0 login");
    let auth0_config = Auth0Config::load();
    let redirect_url = create_authorize_redirect_url(auth0_config);

    Redirect::to(redirect_url)
}

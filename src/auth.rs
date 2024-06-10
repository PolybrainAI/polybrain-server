use super::error::AuthorizationError;
use chrono::{DateTime, TimeZone, Utc};
use log::info;
use reqwest;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{ContentType, Header};
use rocket::response::Redirect;
use rocket::response::{self, Responder};
use rocket::time::OffsetDateTime;
use rocket::tokio::time::Duration;
use rocket::Response;
use rocket::{http::CookieJar, Request};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

pub const USER_CACHE_PATH: &str = "./.auth0-user-cache.json";
const AUTH0_MANAGEMENT_TOKEN_CACHE: &str = "./.auth0-management-token-cache.json";

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

pub enum CompoundResponse {
    Text(String),
    Json(String),
    Redirect(Redirect),
}

// Implement the Responder trait for CompoundResponse
impl<'r> Responder<'r, 'static> for CompoundResponse {
    fn respond_to(self, req: &Request<'_>) -> response::Result<'static> {
        match self {
            CompoundResponse::Text(text) => Response::build()
                .header(ContentType::Plain)
                .sized_body(text.len(), Cursor::new(text))
                .ok(),
            CompoundResponse::Json(json) => Response::build()
                .header(ContentType::JSON)
                .sized_body(json.len(), Cursor::new(json))
                .ok(),
            CompoundResponse::Redirect(redirect) => redirect.respond_to(req),
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
enum Auth0Response {
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
    token: String,
    expires: usize,
}
#[derive(Debug, Deserialize)]
pub struct Auth0ManagementTokenResponse {
    access_token: String,
    expires_in: usize,
}

#[derive(Debug, Serialize)]
struct Auth0ManagementTokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    audience: String,
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
pub async fn get_user_data(user_token: &str) -> Result<UserInfo, Box<dyn std::error::Error>> {
    // Load cache
    let mut cache: HashMap<String, UserInfo> = if Path::new(USER_CACHE_PATH).exists() {
        let mut file = File::open(USER_CACHE_PATH).expect("Failed to open cache file to read");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read cache file");
        serde_json::from_str(&contents).expect("Failed to parse cache file")
    } else {
        // Create an empty cache if the file doesn't exist
        HashMap::new()
    };

    if let Some(user) = cache.get(user_token) {
        println!("Found user in cache");
        return Ok(user.to_owned());
    } else {
        println!("User does not exist in cache");

        // First, fetch preliminary info to get user's id
        let auth0_config = Auth0Config::load();
        let client = reqwest::Client::new();
        let user_preliminary_info_raw = client
            .get(&format!("https://{}/userinfo", auth0_config.domain))
            .header("Authorization", format!("Bearer {user_token}"))
            .send()
            .await?
            .text()
            .await
            .expect("Unable to get Auth0 response as string");

        let user_preliminary_info: UserPreliminaryInfo =
            serde_json::from_str(&user_preliminary_info_raw)
                .inspect_err(|_| {
                    eprintln!(
                        "Auth0 responded with an error or invalid format on UserPreliminaryInfo. Response is:\n{}",
                        user_preliminary_info_raw
                    )
                })?;

        // Then, get the complete info using the user's id
        let user_complete_info_raw = client
            .get(&format!(
                "https://{domain}/api/v2/users/{user_id}",
                domain = auth0_config.domain,
                user_id = user_preliminary_info.sub
            ))
            .bearer_auth(get_auth0_management_token().await)
            .send()
            .await
            .expect("Call to management user endpoint failed")
            .text()
            .await
            .unwrap();

        let mut user_info: UserInfo = serde_json::from_str(&user_complete_info_raw)
            .inspect_err(|_| {
                eprintln!(
                    "Auth0 management API responded with an error or invalid format on UserInfo fetch. Response is:\n{}",
                    user_complete_info_raw
                )
            })
            .unwrap();

        // Manipulate the user info response a bit to work with the React site
        if user_info.username.is_none() {
            let stepin_username = user_info
                .given_name
                .clone()
                .unwrap_or(user_info.name.clone());
            user_info.username = Some(stepin_username)
        }

        // Finally, write new info to the cache
        cache.insert(user_token.to_string(), user_info.clone());
        let cache_file = File::create(USER_CACHE_PATH)
            .expect("Failed to open/create user cache file in write mode");
        serde_json::to_writer_pretty(cache_file, &cache)
            .expect("Failed to write user cache data to file");

        Ok(user_info)
    }
}

/// Gets the Auth0 Management token. Fetches if saved token has expired or
///     does not exist.
///
/// Returns:
///     - The token as a String
pub async fn get_auth0_management_token() -> String {
    // Check to see if there is a saved token
    let token_save_path = Path::new(AUTH0_MANAGEMENT_TOKEN_CACHE);
    let mut token_container: Option<Auth0ManagementTokenSave> = None;

    if token_save_path.exists() {
        info!("A token already exists");

        let token_file = File::open(token_save_path).expect("Could not read Auth0 token file");
        let token_save: Auth0ManagementTokenSave = serde_json::from_reader(token_file)
            .expect("The Auth0 management token save is misformed");
        let expiration_date = Utc.timestamp_micros(token_save.expires as i64).unwrap();

        if expiration_date < Utc::now() + Duration::from_secs(5 * 60) {
            warn!("Auth0 management token has expired")
        } else {
            info!(
                "Using existing Auth0 management token; expires in {} minutes",
                (expiration_date - Utc::now()).num_minutes()
            );
            token_container = Some(token_save);
        }
    }

    if token_container.is_none() {
        // Fetch a token from the API
        let auth0_config = Auth0Config::load();

        let token_request = Auth0ManagementTokenRequest {
            grant_type: "client_credentials".to_owned(),
            client_id: auth0_config.client_id,
            client_secret: auth0_config.secret,
            audience: format!("https://{}/api/v2/", auth0_config.domain),
        };

        let token_response_raw: String = reqwest::Client::new()
            .post(format!(
                "https://{AUTH0_DOMAIN}/oauth/token",
                AUTH0_DOMAIN = auth0_config.domain
            ))
            .json(&token_request)
            .send()
            .await
            .expect("Failed to get Auth0 management key")
            .text()
            .await
            .expect("Failed to serialize Auth0 management API response for management key");

        let token_response: Auth0ManagementTokenResponse =
            serde_json::from_str(&token_response_raw)
                .map_err(|_| {
                    println!(
                "Failed to serialize response into Auth0ManagementTokenResponse:\nResponse is:\n{}",
                token_response_raw
            )
                })
                .unwrap();

        // Write the response to the save file
        let expiration_date = Utc::now() + Duration::from_secs(token_response.expires_in as u64);
        let token_save = Auth0ManagementTokenSave {
            token: token_response.access_token,
            expires: expiration_date.timestamp_micros() as usize,
        };

        let token_file = File::create(token_save_path)
            .expect("Failed open/create the Auth0 management token save file in write mode");
        serde_json::to_writer(token_file, &token_save)
            .expect("Failed to write new Auth0 management token save");

        token_container = Some(token_save);

        info!("Refreshed Auth0 management token");
    }

    return token_container.unwrap().token;
}

/// Redirects the user to the Auth0 login page
#[get("/auth0/login", rank = 0)]
pub async fn auth0_login() -> Redirect {
    println!("Redirecting to Auth0 login");
    let auth0_config = Auth0Config::load();
    let redirect_url = create_authorize_redirect_url(auth0_config);

    Redirect::to(redirect_url)
}

/// Redirects the user to the Auth0 logout page
#[get("/auth0/logout", rank = 0)]
pub async fn auth0_logout(cookies: &CookieJar<'_>,) -> Redirect {

    info!("Removing token");
    if let Some(cookie) = cookies.get("polybrain-session") {
        cookies.remove(cookie.to_owned());
        };

    info!("Redirecting to Auth0 logout");
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
        "{}/portal",
        std::env::var("API_BASE").expect("API_BASE must be set.")
    );
    println!("Redirecting to {user_page}");
    Redirect::to(user_page)
}

#[get("/auth0/user-data", rank = 0)]
pub async fn auth0_user_data(
    cookies: &CookieJar<'_>,
) -> Result<CompoundResponse, AuthorizationError> {
    if let Some(token) = cookies.get("polybrain-session") {
        let user_info = get_user_data(token.value()).await;

        if let Ok(info) = &user_info {
            Ok(CompoundResponse::Text(
                serde_json::to_string_pretty(info).unwrap(),
            ))
        } else {
            warn!("User has an invalid token. Logging out.");
            Ok(CompoundResponse::Redirect(Redirect::to(format!(
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

pub struct Cors;

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new(
            "Access-Control-Allow-Origin",
            "http://localhost:3000",
        ));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "Content-Type"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

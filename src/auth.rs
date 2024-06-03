use super::error::AuthorizationError;
use log::{info, debug, error};
use reqwest;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::response::Redirect;
use rocket::tokio::time::{sleep, Duration};
use rocket::Response;
use rocket::{http::CookieJar, Request};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::SystemTime;
use chrono::{DateTime, Utc, TimeZone};

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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserInfo {
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
#[derive(Debug, Serialize, Deserialize)]
pub struct Auth0ManagementTokenResponse {
    access_token: String,
    expires_in: usize,
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

pub async fn get_user_data(user_token: &str) -> UserInfo {
    // Load cache
    let cache_path = ".user-info-cache.json";
    let mut cache: HashMap<String, UserInfo> = if Path::new(cache_path).exists() {
        let mut file = File::open(cache_path).expect("Failed to open cache file to read");
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
        return user.to_owned();
    } else {
        println!("User does not exist in cache")
    }

    let client = reqwest::Client::new();
    let user_info_url = format!("https://{}/userinfo", Auth0Config::load().domain);

    let mut headers = HashMap::new();
    headers.insert("Authorization", format!("Bearer {user_token}"));

    println!("Getting user data with headers: {:?}", headers);

    for retry in 1..5 {
        let user_info_raw = client
            .get(&user_info_url)
            .header("Authorization", format!("Bearer {user_token}"))
            .send()
            .await
            .inspect_err(|err| eprintln!("Failed to fetch user info from Auth0: {err}"))
            .unwrap()
            .text()
            .await
            .expect("Unable to get Auth0 response as string");

        println!("Auth0 responded with:\n {user_info_raw}");

        let user_info_response: Auth0Response = serde_json::from_str(&user_info_raw).expect(
            &format!("Auth0 responded with foreign response: {user_info_raw}"),
        );

        if let Auth0Response::UserInfo(info) = user_info_response {
            println!("Adding user to cache");
            cache.insert(user_token.to_owned(), info.clone());

            let mut cache_file =
                File::create(cache_path).expect("Failed to open cache file to write");
            cache_file
                .write_all(
                    serde_json::to_string(&cache)
                        .expect("Failed to serialize cache")
                        .as_bytes(),
                )
                .expect("Failed to write to cache file");

            println!("Sending user info: {:?}", info);
            return info;
        } else if let Auth0Response::Auth0Error(error) = user_info_response {
            eprintln!(
                "[{retry}/5] Auth0 responded with error: {}. Attempting with exponential backoff",
                error.error_description
            );
            sleep(Duration::from_secs(u64::pow(retry, 2))).await;
        }
    }

    panic!("Unable to reconcile Auth0 error!");
}


/// Gets the Auth0 Management token. Fetches if saved token has expired or
///     does not exist.
/// 
/// Returns:
///     - The token as a String
pub async fn get_auth0_management_token() -> String{


    // Check to see if there is a saved token
    let token_save_path = Path::new(".auth0-management.json");
    let mut token_container: Option<Auth0ManagementTokenSave> = None;


    
    if token_save_path.exists() {
        info!("A token already exists");


        let token_file = File::open(token_save_path).expect("Could not read Auth0 token file");
        let token_save: Auth0ManagementTokenSave = serde_json::from_reader(token_file).expect("The Auth0 management token save is misformed");
        let expiration_date = Utc.timestamp_micros(token_save.expires as i64).unwrap();

        if expiration_date < Utc::now() + Duration::from_secs(5*60){
            warn!("Auth0 management token has expired")
        }
        else {
            info!("Using existing Auth0 management token; expires in {} minutes", (expiration_date - Utc::now()).num_minutes());
            token_container = Some(token_save);
        }

    }

    if token_container.is_none() {

        // Fetch a token from the API
        let auth0_config = Auth0Config::load();
        let token_response: Auth0ManagementTokenResponse = reqwest::Client::new()
        .post(format!("https://{AUTH0_DOMAIN}/oauth/token", AUTH0_DOMAIN=auth0_config.domain))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("grant_type=client_credentials&\
                    client_id={AUTH0_CLIENT_ID}&\
                    client_secret=%7B{AUTH0_CLIENT_SECRET}%7D&audience=https%3A%2F%2F{AUTH0_DOMAIN}%2Fapi%2Fv2%2F",
                    
                    AUTH0_CLIENT_SECRET=auth0_config.secret,
                    AUTH0_CLIENT_ID = auth0_config.client_id,
                    AUTH0_DOMAIN = auth0_config.domain
                ))
        .send()
        .await
        .expect("Failed to get Auth0 management key")
        .json()
        .await
        .expect("Failed to serialize Auth0 management API response for management key");

        // Write the response to the save file

        let expiration_date = Utc::now() + Duration::from_secs(token_response.expires_in as u64);

        let token_save = Auth0ManagementTokenSave{
            token: token_response.access_token,
            expires: expiration_date.timestamp_micros() as usize
        };

        let token_file = File::create(token_save_path).expect("Failed open/create the Auth0 management token save file in write mode");
        serde_json::to_writer(token_file, &token_save).expect("Failed to write new Auth0 management token save");

        token_container = Some(token_save);
            
        info!("Refreshed Auth0 management token");
    }

    return token_container.unwrap().token

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
pub async fn auth0_logout() -> Redirect {
    println!("Redirecting to Auth0 logout");
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
pub async fn auth0_user_data(cookies: &CookieJar<'_>) -> Result<String, AuthorizationError> {
    if let Some(token) = cookies.get("polybrain-session") {
        let user_info = get_user_data(token.value()).await;
        Ok(serde_json::to_string_pretty(&user_info).unwrap())
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
        response.set_header(Header::new(
            "Access-Control-Allow-Headers",
            "Content-Type",
        ));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

/*

Exposed Database Endpoints
Endpoint handles that interface with the MongoClient (in ./util.rs)

Copyright Polybrain 2024

*/

use crate::{
    auth::types::{Auth0Config, UserInfo},
    database::{types::UserUploadRequest, util::MongoUtil},
};
use std::{collections::HashMap, fs::File, io::Read, path::Path};

use mongodb::bson::doc;
use reqwest::StatusCode;

use crate::{
    auth::util::{get_auth0_management_token, get_user_data, USER_CACHE_PATH},
    util::error::BadRequest,
};
use log::{warn};
use rocket::{http::CookieJar, serde::json::Json, tokio::sync::Mutex};
use rocket::{response::Redirect, State};

use super::types::{CredentialType, UserCredentialView};

/// Encrypts and uploads credentials
#[allow(private_interfaces)]
#[post("/credentials/upload", data = "<data>")]
pub async fn credentials_upload(
    cookies: &CookieJar<'_>,
    data: Json<UserUploadRequest>,
    mongo_util: &State<Mutex<MongoUtil>>,
) -> Result<String, BadRequest> {
    // Load the user
    let user_info: UserInfo;
    if let Some(token) = cookies.get("polybrain-session") {
        user_info = match get_user_data(token.value()).await {
            Ok(i) => i,
            Err(_) => return Err(BadRequest::new("Bad Credentials")),
        };
    } else {
        return Err(BadRequest::new("You must be logged in to upload data"));
    }

    // Create a vector of credentials to upload
    let mut credential_uploads: Vec<CredentialType> = Vec::new();

    if let Some(onshape_access) = &data.onshape_access {
        if onshape_access.len() != 24 {
            return Err(BadRequest::new("OnShape Access Key has an invalid format"));
        }
        println!("adding OnShape Access key to {}", user_info.email);
        credential_uploads.push(CredentialType::OnshapeAccess(onshape_access.to_owned()));
    }
    if let Some(onshape_secret) = &data.onshape_secret {
        if onshape_secret.len() != 48 {
            return Err(BadRequest::new("OnShape Secret Key has an invalid format"));
        }

        println!("adding OnShape Secret key to {}", user_info.email);
        credential_uploads.push(CredentialType::OnshapeSecret(onshape_secret.to_owned()));
    }
    if let Some(openai_api) = &data.openai_api {
        if openai_api.len() != 51 {
            return Err(BadRequest::new("OpenAI API key has an invalid format"));
        }
        println!("adding OpenAI API key to {}", user_info.email);
        credential_uploads.push(CredentialType::OpenAiAPI(openai_api.to_owned()));
    }

    // Upload credentials
    _ = mongo_util
        .lock()
        .await
        .add_credentials(&user_info, credential_uploads)
        .await;

    Ok("{\"success\": true}".to_owned())
}

/// To be removed; CORS fix
#[options("/credentials/upload")]
pub async fn credentials_upload_preflight() {}

/// Previews which credentials have been uploaded
#[get("/credentials/preview")]
pub async fn credentials_preview(
    cookies: &CookieJar<'_>,
    mongo_util: &State<Mutex<MongoUtil>>,
) -> Result<String, BadRequest> {
    // Load the user
    let user_info: UserInfo;
    if let Some(token) = cookies.get("polybrain-session") {
        user_info = get_user_data(token.value()).await.unwrap();
    } else {
        return Err(BadRequest::new(
            "You must be logged in to view your credentials",
        ));
    }

    // Iterate over different credential types
    let mut user_preview = UserCredentialView::all_false();
    let user_document = mongo_util.lock().await.get_user(&user_info.user_id).await;

    if let Some(user_document) = user_document {
        user_preview.has_onshape_access = user_document.credentials.onshape_access.is_some();
        user_preview.has_onshape_secret = user_document.credentials.onshape_secret.is_some();
        user_preview.has_openai_api = user_document.credentials.open_ai_api.is_some();
    } else {
        warn!("user requested info, but they do not exist in db. returning all false values for preview");
    }

    Ok(serde_json::to_string_pretty(&user_preview).unwrap())
}

/// Deletes the user and their credentials from the database. Also removes from
/// Auth0 DB.
#[get("/user/delete-self")]
pub async fn user_delete_self(
    cookies: &CookieJar<'_>,
    mongo_util: &State<Mutex<MongoUtil>>,
) -> Result<Redirect, BadRequest> {
    // Load the user
    let user_info: UserInfo;
    let user_token: &str;
    if let Some(token) = cookies.get("polybrain-session") {
        user_info = get_user_data(token.value()).await.unwrap();
        user_token = token.value();
    } else {
        return Err(BadRequest::new(
            "Session token must be present to identify user for deletion",
        ));
    }

    // Delete user from Mongodb
    mongo_util
        .lock()
        .await
        .delete_user(&user_info.user_id)
        .await;

    // Delete user from Auth0 db
    let delete_response = reqwest::Client::new()
        .delete(&format!(
            "https://{domain}/api/v2/users/{user_id}",
            domain = Auth0Config::load().domain,
            user_id = user_info.user_id
        ))
        .bearer_auth(get_auth0_management_token().await)
        .send()
        .await
        .expect("Call to management user endpoint failed");

    match delete_response.status() {
        StatusCode::NO_CONTENT => {
            println!("Successfully deleted user {} from Auth0", user_info.user_id)
        }
        _ => {
            let status_code = delete_response.status().as_u16();
            let response_text = delete_response.text().await.unwrap();
            error!(
                "Unable to delete user {user_id} from Auth0. Got <{err_code}> code Error:\n{err}",
                user_id = user_info.user_id,
                err_code = status_code,
                err = response_text
            )
        }
    }

    // Remove user from cache
    if Path::new(USER_CACHE_PATH).exists() {
        let mut file_read = File::open(USER_CACHE_PATH).expect("Failed to open cache file to read");
        let mut contents = String::new();
        file_read
            .read_to_string(&mut contents)
            .expect("Failed to read cache file");
        drop(file_read); // close the file to help w io errors

        let file_write = File::create(USER_CACHE_PATH).expect("Failed to open cache file to read");
        let mut cache: HashMap<String, UserInfo> =
            serde_json::from_str(&contents).expect("Failed to parse cache file");
        cache.remove(user_token);

        serde_json::to_writer_pretty(file_write, &cache)
            .expect("Failed to write updated user cache back to file");
        println!("Successfully removed user from cache")
    }

    Ok(Redirect::to(format!(
        "{API_BASE}/auth0/logout",
        API_BASE = std::env::var("API_BASE").expect("API_BASE must be set.")
    )))
}

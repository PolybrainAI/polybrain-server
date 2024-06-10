/*

Database operations

*/

use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::Path,
};

use mongodb::{
    bson::doc,
    options::{ClientOptions, ServerApi, ServerApiVersion},
    Client, Collection,
};
use reqwest::StatusCode;
use serde::Serialize;

use crate::{
    auth::{get_auth0_management_token, get_user_data, Auth0Config, UserInfo, USER_CACHE_PATH},
    encryption::encrypt,
    error::BadRequest,
};
use log::{info, warn};
use rocket::{
    http::CookieJar,
    serde::{self, json::Json, Deserialize},
    tokio::sync::Mutex,
};
use rocket::{response::Redirect, State};

#[derive(Debug, Deserialize)]
struct UserUploadRequest {
    onshape_access: Option<String>,
    onshape_secret: Option<String>,
    openai_api: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct UserCredentialView {
    has_onshape_access: bool,
    has_onshape_secret: bool,
    has_openai_api: bool,
}

impl UserCredentialView {
    pub fn all_false() -> UserCredentialView {
        UserCredentialView {
            has_onshape_access: false,
            has_onshape_secret: false,
            has_openai_api: false,
        }
    }
}

#[derive(Debug)]
pub enum CredentialType {
    OnshapeAccess(String),
    OnshapeSecret(String),
    OpenAiAPI(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserDocumentCredentials {
    pub onshape_access: Option<String>,
    pub onshape_secret: Option<String>,
    pub open_ai_api: Option<String>,
}

impl UserDocumentCredentials {
    pub fn empty() -> UserDocumentCredentials {
        UserDocumentCredentials {
            onshape_access: None,
            onshape_secret: None,
            open_ai_api: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserDocument {
    user_id: String,
    email: String,
    credentials: UserDocumentCredentials,
}

#[derive(Debug)]
pub struct Auth0Manager {
    _config: Auth0Config,
}
impl Auth0Manager {
    fn new() -> Self {
        Auth0Manager {
            _config: Auth0Config::load(),
        }
    }
}
#[derive(Debug)]
pub struct MongoUtil {
    mongo_client: Client,
    _auth0_client: Auth0Manager,
    user_collection: Collection<UserDocument>,
}

impl MongoUtil {
    pub async fn new() -> Result<Self, mongodb::error::Error> {
        let mut client_options =
            ClientOptions::parse(std::env::var("MONGODB_URL").expect("MONGODB_URL must be set"))
                .await?;

        // Set the server_api field of the client_options object to set the version of the Stable API on the client
        let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
        client_options.server_api = Some(server_api);

        // Get a handle to the cluster
        let mongo_client = Client::with_options(client_options)?;
        let user_collection = mongo_client
            .database(
                std::env::var("MONGODB_DATABASE")
                    .expect("MONGODB_DATABASE must be set")
                    .as_str(),
            )
            .collection("users");

        let new_instance = MongoUtil {
            mongo_client,
            user_collection,
            _auth0_client: Auth0Manager::new(),
        };

        new_instance.ping().await.expect("MongoDB ping failed");
        Ok(new_instance)
    }
    pub async fn ping(&self) -> Result<(), mongodb::error::Error> {
        _ = &self
            .mongo_client
            .database("admin")
            .run_command(doc! {"ping": 1}, None)
            .await?;
        Ok(())
    }

    pub async fn get_user(&self, user_id: &str) -> Option<UserDocument> {
        let filter = doc! { "user_id": user_id };
        let user = self
            .user_collection
            .find_one(filter.clone(), None)
            .await
            .expect("Fatal MongoDB error on user query");
        if let Some(_) = user {
            info!("successfully fetched user with id {user_id}");
        } else {
            warn!("user with id {user_id} does not exist in MongoDB");
        }
        user
    }

    /// Adds a new user to mongo
    pub async fn add_user(
        &mut self,
        user_document: &UserDocument,
    ) -> Result<(), mongodb::error::Error> {
        _ = &mut self.user_collection.insert_one(user_document, None).await?;
        Ok(())
    }

    /// Deletes a user from mongo
    pub async fn delete_user(&self, user_id: &str) -> bool {
        let filter = doc! {"user_id": user_id};
        let result = self
            .user_collection
            .delete_one(filter.clone(), None)
            .await
            .expect("Fatal MongoDB error on user query");
        if result.deleted_count > 0 {
            info!("Successfully deleted user {user_id} contents from MongoDB");
            true
        } else {
            warn!("Unable to delete user {user_id} contents from MongoDB. Does the user exist?");
            false
        }
    }

    pub async fn add_credentials(
        &mut self,
        target_user: &UserInfo,
        credential_updates: Vec<CredentialType>,
    ) -> Result<(), mongodb::error::Error> {
        let user_id = &target_user.user_id;

        let mut user: UserDocument;

        // Find the user by user_id
        if let Some(user_info) = &self.get_user(user_id).await {
            user = user_info.to_owned();
        } else {
            // Create a new user if one doesn't already exist
            warn!("info: adding a new user to the db");
            let user_document = UserDocument {
                user_id: user_id.to_owned(),
                email: target_user.email.clone(),
                credentials: UserDocumentCredentials::empty(),
            };
            _ = &mut self.add_user(&user_document).await?;
            user = user_document
        }

        // Load token into model
        for credential_type in credential_updates {
            match credential_type {
                CredentialType::OnshapeAccess(token) => {
                    user.credentials.onshape_access = Some(encrypt(token.as_bytes()));
                }
                CredentialType::OnshapeSecret(token) => {
                    user.credentials.onshape_secret = Some(encrypt(token.as_bytes()));
                }
                CredentialType::OpenAiAPI(token) => {
                    user.credentials.open_ai_api = Some(encrypt(token.as_bytes()));
                }
            }
        }

        let filter = doc! { "user_id": user_id };
        let replace_result = &self
            .user_collection
            .replace_one(filter, &user, None)
            .await?;

        info!("updated user. result: {:?}", replace_result);

        Ok(())
    }
}

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
            Err(_) => {
                return Err(BadRequest::new("Bad Credentials"))
            }
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
        info!("adding OnShape Access key to {}", user_info.email);
        credential_uploads.push(CredentialType::OnshapeAccess(onshape_access.to_owned()));
    }
    if let Some(onshape_secret) = &data.onshape_secret {
        if onshape_secret.len() != 48 {
            return Err(BadRequest::new("OnShape Secret Key has an invalid format"));
        }

        info!("adding OnShape Secret key to {}", user_info.email);
        credential_uploads.push(CredentialType::OnshapeSecret(onshape_secret.to_owned()));
    }
    if let Some(openai_api) = &data.openai_api {
        if openai_api.len() != 51 {
            return Err(BadRequest::new("OpenAI API key has an invalid format"));
        }
        info!("adding OpenAI API key to {}", user_info.email);
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

#[options("/credentials/upload")]
pub async fn credentials_upload_preflight() {}

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
            info!("Successfully deleted user {} from Auth0", user_info.user_id)
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
        file_read.read_to_string(&mut contents)
        .expect("Failed to read cache file");
        drop(file_read); // close the file to help w io errors
        
        let file_write = File::create(USER_CACHE_PATH).expect("Failed to open cache file to read");
        let mut cache: HashMap<String, UserInfo> =
            serde_json::from_str(&contents).expect("Failed to parse cache file");
        cache.remove(user_token);

        serde_json::to_writer_pretty(file_write, &cache)
            .expect("Failed to write updated user cache back to file");
        info!("Successfully removed user from cache")
    }

    

    Ok(Redirect::to(format!(
        "{API_BASE}/auth0/logout",
        API_BASE = std::env::var("API_BASE").expect("API_BASE must be set.")
    )))
}

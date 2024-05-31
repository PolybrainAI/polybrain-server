
use mongodb::{bson::doc, options::{ClientOptions, ServerApi, ServerApiVersion}, Client, Collection};
use serde::Serialize;

use crate::{auth::{get_user_data, Auth0Config, UserInfo}, error::BadRequest};
use rocket::{http::CookieJar, serde::{json::Json, Deserialize}, tokio::sync::Mutex};
use rocket::State;
use log::{info, warn};





#[derive(Debug, Deserialize)]
struct UserUploadRequest {
    onshape_access: Option<String>,
    onshape_secret: Option<String>,
    openai_api: Option<String>
}

#[derive(Debug)]
enum CredentialType{
  OnshapeAccess(String),
  OnshapeSecret(String),
  OpenAiAPI(String)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserDocumentCredentials{
  pub onshape_access: Option<String>,
  pub onshape_secret: Option<String>,
  pub open_ai_api: Option<String>
}

impl UserDocumentCredentials{
  pub fn empty() -> UserDocumentCredentials{
    UserDocumentCredentials{
      onshape_access: None,
      onshape_secret: None,
      open_ai_api: None
    }
  }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UserDocument{
    user_id: String,
    email: String,
    credentials: UserDocumentCredentials
}

#[derive(Debug)]
pub struct Auth0Manager{
  config: Auth0Config
}
impl Auth0Manager{
  fn new() -> Self{
    Auth0Manager{
      config: Auth0Config::load()
    }
  }
}


pub struct SharedMongoUtil(pub Mutex<MongoUtil>);


#[derive(Debug)]
pub struct MongoUtil {
    mongo_client: Client,
    auth0_client: Auth0Manager,
    user_collection: Collection<UserDocument>
}

impl MongoUtil {
    pub async fn new() -> Result<Self, mongodb::error::Error>{
        let mut client_options =
            ClientOptions::parse(std::env::var("MONGODB_URL").expect("MONGODB_URL must be set")).await?;

        // Set the server_api field of the client_options object to set the version of the Stable API on the client
        let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
        client_options.server_api = Some(server_api);

        // Get a handle to the cluster
        let mongo_client = Client::with_options(client_options)?;
        let user_collection = mongo_client.database(std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set").as_str()).collection("users");

        let new_instance = MongoUtil{
          mongo_client,
          user_collection,
          auth0_client: Auth0Manager::new()
      };

        new_instance.ping().await.expect("MongoDB ping failed");
        Ok(new_instance)
    }
    pub async fn ping(&self) -> Result<(), mongodb::error::Error>{
      _ = &self.mongo_client.database("admin").run_command(doc!{"ping": 1}, None).await?;
      Ok(())
    }


    pub async fn get_user(&self, user_id: &str) -> Option<UserDocument>{
      let filter = doc! { "user_id": user_id };
      let user = self.user_collection.find_one(filter.clone(), None).await.expect("Fatal MongoDB error on user query");
      if let Some(_) = user{
        info!("successfully fetched user with id {user_id}");
      }
      else{
        warn!("user with id {user_id} does not exist in MongoDB");
      }
      user
    }

    /// Adds a new user to mongo
    pub async fn add_user(&mut self, user_document: &UserDocument) -> Result<(), mongodb::error::Error>{
      _ = &mut self.user_collection.insert_one(user_document, None).await?;
      Ok(())
    }

    pub async fn add_credentials(&mut self, target_user: &UserInfo, credential_updates: Vec<CredentialType>) -> Result<(), mongodb::error::Error>{
      let user_id = &target_user.sub;

      let mut user: UserDocument;

      // Find the user by user_id
      if let Some(user_info) = &self.get_user(user_id).await{
        user = user_info.to_owned();
      }
      else{
        // Create a new user if one doesn't already exist
        warn!("info: adding a new user to the db");
        let user_document = UserDocument{
          user_id: user_id.to_owned(),
          email: target_user.email.clone(),
          credentials: UserDocumentCredentials::empty()
        };
        _ = &mut self.add_user(&user_document).await?;
        user = user_document
      }

      // Load token into model
      for credential_type in credential_updates{
        match credential_type{
          CredentialType::OnshapeAccess(token) => {
            user.credentials.onshape_access = Some(token);
          }
          CredentialType::OnshapeSecret(token) => {
            user.credentials.onshape_secret = Some(token);
          }
          CredentialType::OpenAiAPI(token) => {
            user.credentials.open_ai_api = Some(token);
          }
        }
      }

      let filter = doc! { "user_id": user_id };
      let replace_result = &self.user_collection.replace_one(filter, &user, None).await?;

      info!("updated user. result: {:?}", replace_result);

      Ok(())




    }
}

#[allow(private_interfaces)]
#[post("/credentials/upload", data = "<data>")]
pub async fn credentials_upload(cookies: &CookieJar<'_>, data: Json<UserUploadRequest>, mongo_util: &State<Mutex<MongoUtil>>) -> Result<String, BadRequest> {

  let user_info: UserInfo;


  println!("Inner ping:");
  mongo_util.lock().await.ping().await.unwrap();
  println!("Inner ping done!");

  if let Some(token) = cookies.get("polybrain-session") {
    user_info = get_user_data(token.value()).await;
  } else {
      return Err(BadRequest::new(
          "You must be logged in to upload data",
      ));
  }

  let mut credential_uploads: Vec<CredentialType> = Vec::new();

  if let Some(onshape_access) = &data.onshape_access{
    if onshape_access.len() != 24{
      return Err(BadRequest::new("OnShape Access Key has an invalid format"));
    }
    println!("Adding OnShape Access key to {}", user_info.email);
    credential_uploads.push(CredentialType::OnshapeAccess(onshape_access.to_owned()));
  }
  if let Some(onshape_secret) = &data.onshape_secret{
    if onshape_secret.len() != 48{
      return Err(BadRequest::new("OnShape Secret Key has an invalid format"));
    }
    
    println!("Adding OnShape Secret key to {}", user_info.email);
    credential_uploads.push(CredentialType::OnshapeSecret(onshape_secret.to_owned()));
  }
  if let Some(openai_api) = &data.openai_api{
    if openai_api.len() != 51{
      return Err(BadRequest::new("OpenAI API key has an invalid format"));
    }
    println!("Adding OpenAI API key to {}", user_info.email);
    credential_uploads.push(CredentialType::OpenAiAPI(openai_api.to_owned()));
  }

  info!("Uploading the following credentials: {:?}", credential_uploads);
  _ = mongo_util.lock().await.add_credentials(&user_info, credential_uploads).await;

  Ok("{\"success\": true}".to_owned())
  
}

#[options("/credentials/upload")]
pub async fn credentials_upload_preflight(){}
/*

MongoDB Utility
Wraps database operations with Polybrain schema

Copyright Polybrain 2024

*/

use crate::{auth::types::UserInfo, database::types::UserDocumentCredentials};

use mongodb::{
    bson::doc,
    options::{ClientOptions, ServerApi, ServerApiVersion},
    Client, Collection,
};

use crate::auth::encryption::encrypt;
use log::{info, warn};

use super::types::{Auth0Manager, CredentialType, UserDocument};

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
        if user.is_some() {
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

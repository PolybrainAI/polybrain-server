/*

MongoDB Types
Different types that are stored in the DB

Copyright Polybrain 2024

*/

use serde::{Deserialize, Serialize};

use crate::auth::types::Auth0Config;

#[derive(Debug, Deserialize)]
pub struct UserUploadRequest {
    pub onshape_access: Option<String>,
    pub onshape_secret: Option<String>,
    pub openai_api: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserCredentialView {
    pub has_onshape_access: bool,
    pub has_onshape_secret: bool,
    pub has_openai_api: bool,
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
    pub user_id: String,
    pub email: String,
    pub credentials: UserDocumentCredentials,
}

#[derive(Debug)]
pub struct Auth0Manager {
    _config: Auth0Config,
}
impl Auth0Manager {
    pub fn new() -> Self {
        Auth0Manager {
            _config: Auth0Config::load(),
        }
    }
}

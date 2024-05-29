#[macro_use] extern crate rocket;
use std::collections::HashMap;
use rocket::{custom, tokio};
use rocket::form::validate::Len;
use rocket::http::Status;
use rocket::outcome::{Outcome};
use rocket::request::{Request, FromRequest};


#[derive(PartialEq)]
pub struct ApiKey<'r>(pub(crate) &'r str);

#[derive(Debug)]
pub enum ApiKeyError {
    MissingError,
    InvalidError,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ApiKey<'r> {
    type Error = ApiKeyError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<ApiKey<'r>, (Status, ApiKeyError), Status> {
        /// Returns true if `key` is a valid API key string.
        fn is_valid(key: &str) -> bool {
            key.len() > 0
        }

        match req.headers().get_one("x-api-key") {
            None => Outcome::Error((Status::BadRequest, ApiKeyError::MissingError)),
            Some(key) if is_valid(key) => Outcome::Success(ApiKey(key)),
            Some(_) => Outcome::Error((Status::BadRequest, ApiKeyError::InvalidError)),
        }
    }
}

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index])
}
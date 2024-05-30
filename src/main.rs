#[macro_use]
extern crate rocket;
use std::path::{Path, PathBuf};

use dotenv::dotenv;
use rocket::fs::NamedFile;
mod auth;
mod error;

#[get("/<_..>", rank = 5)]
async fn fallback_url() -> Option<NamedFile> {
    let build_env = std::env::var("REACT_BUILD").expect("REACT_BUILD must be set");
    let build_index = Path::new(build_env.as_str());
    NamedFile::open(build_index.join("index.html")).await.ok()
}


#[get("/<file..>", rank=4)]
async fn files(file: PathBuf) -> Option<NamedFile> {
    let build_env = std::env::var("REACT_BUILD").expect("REACT_BUILD must be set");
    let build_index = Path::new(build_env.as_str());
    NamedFile::open(build_index.join("static/").join(file)).await.ok()
}


#[launch] 
fn rocket() -> _ {
    dotenv().ok();
    rocket::build()
    .attach(auth::Cors)
    .mount("/", routes![auth::auth0_login, auth::auth0_callback, auth::auth0_user_data, auth::auth0_logout])
    .mount("/static", routes![files,])
    .mount("/", routes![fallback_url,])
}

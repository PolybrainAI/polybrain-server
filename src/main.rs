/*

Rocket Entry Point
Connects all handles to main rocket instance

Copyright Polybrain 2024

*/

#[macro_use]
extern crate rocket;
use std::path::{Path, PathBuf};

use dotenv::dotenv;
use rocket::{fs::NamedFile, tokio::sync::Mutex};
mod auth;
mod database;
mod util;

#[get("/<_..>", rank = 5)]
async fn fallback_url() -> Option<NamedFile> {
    let build_env = std::env::var("REACT_BUILD").expect("REACT_BUILD must be set");
    let build_index = Path::new(build_env.as_str());
    NamedFile::open(build_index.join("index.html")).await.ok()
}

#[get("/<file..>", rank = 4)]
async fn files(file: PathBuf) -> Option<NamedFile> {
    let build_env = std::env::var("REACT_BUILD").expect("REACT_BUILD must be set");
    let build_index = Path::new(build_env.as_str());
    NamedFile::open(build_index.join("static/").join(file))
        .await
        .ok()
}

#[launch]
async fn rocket() -> _ {
    dotenv().unwrap();

    let mongo_util = database::util::MongoUtil::new().await.unwrap();

    rocket::build()
        .attach(auth::util::Cors)
        .mount(
            "/",
            routes![
                auth::endpoints::auth0_login,
                auth::endpoints::auth0_callback,
                auth::endpoints::auth0_user_data,
                auth::endpoints::auth0_logout
            ],
        )
        .mount(
            "/",
            routes![
                database::endpoints::credentials_upload,
                database::endpoints::credentials_upload_preflight,
                database::endpoints::credentials_preview,
                database::endpoints::user_delete_self,
            ],
        )
        .mount("/static", routes![files,])
        .mount("/", routes![fallback_url,])
        .manage(Mutex::new(mongo_util))
}

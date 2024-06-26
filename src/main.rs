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
mod api;
mod auth;
mod database;
mod util;

/// Serve files from react dist
#[get("/<file..>", rank = 4)]
async fn files(file: PathBuf) -> Option<NamedFile> {
    let build_env = std::env::var("REACT_BUILD").expect("REACT_BUILD must be set");
    let build_index = Path::new(build_env.as_str());

    // serve files if requested
    if let Ok(filepath) = build_index.join(file).canonicalize() {
        if filepath.exists()
            && filepath.is_file()
            && filepath.starts_with(build_index.canonicalize().unwrap())
        {
            println!("Serving file: {:?}", &filepath);
            return NamedFile::open(filepath).await.ok();
        }
    }
    // otherwise, serve react
    println!("No matching file, serving react");
    NamedFile::open(build_index.join("index.html")).await.ok()
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
        .mount(
            "/api",
            routes![api::audio::audio_speak, api::audio::audio_speak_preflight],
        )
        .mount("/", routes![files,])
        .manage(Mutex::new(mongo_util))
}

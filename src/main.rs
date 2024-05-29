#[macro_use]
extern crate rocket;
use dotenv::dotenv;

mod auth;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[launch] 
fn rocket() -> _ {
    dotenv().ok();
    rocket::build().mount("/api/", routes![index, auth::auth0_login, auth::auth0_callback, auth::auth0_user_data])
}

use rocket::http::hyper::body::Bytes;

use rocket::response::stream::ByteStream;
use rocket::State;
use rocket::{serde::json::Json, tokio::sync::Mutex};
use serde_json::json;

use crate::api::types::SpeakRequest;
use crate::auth::encryption::_decrypt;
use crate::auth::types::UserInfo;
use crate::auth::util::{get_user_data, AuthToken};
use crate::database::util::MongoUtil;
use crate::util::error::BadRequest;

#[options("/audio/speak")]
pub async fn audio_speak_preflight() {} // CORS fix

#[post("/audio/speak", data = "<data>")]
pub async fn audio_speak(
    auth_token: AuthToken,
    data: Json<SpeakRequest>,
    mongo_util: &State<Mutex<MongoUtil>>,
) -> Result<ByteStream![Bytes], BadRequest> {
    // ) -> Result<String, BadRequest> {
    println!("matched endpoint");

    let user_info: UserInfo = get_user_data(&auth_token.0).await.unwrap();

    println!("got user data?");

    // load and decrypt user's openai key
    let user_document = mongo_util.lock().await.get_user(&user_info.user_id).await;
    let openai_key: String;
    match user_document {
        Some(doc) => {
            let openai_key_encrypted = doc.credentials.open_ai_api;

            match openai_key_encrypted {
                Some(key) => {
                    openai_key = _decrypt(&key);
                }
                None => return Err(BadRequest::new("Account has no OpenAI API key loaded")),
            }
        }
        None => {
            return Err(BadRequest::new(
                "You must load an OpenAI API key before referencing the speak api",
            ));
        }
    }

    // start downloading mp3
    let client = reqwest::Client::new();
    let payload = json!({
        "model": "tts-1",
        "input": data.text,
        "voice": "alloy",
    });
    println!("sending json payload to OpenAI: {:#}", payload);
    let mut response = client
        .post("https://api.openai.com/v1/audio/speech".to_string())
        .bearer_auth(openai_key)
        .json(&payload)
        .send()
        .await
        .expect("failed to call openai speech api");

    if !response.status().is_success() {
        println!(
            "OpenAI Speech API returned error:\n{}",
            response.text().await.unwrap()
        );
        return Err(BadRequest::new("Internal Error")); // TODO: fix error handling
    }

    let stream = ByteStream! {
        while let Some(chunk) = response.chunk().await.unwrap() {
            yield chunk;
        };

    };
    Ok(stream)
}

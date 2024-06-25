use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct SpeakRequest{
    pub text: String
}
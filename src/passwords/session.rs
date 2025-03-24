use crate::endpoint::{Endpoint, EndpointInfo};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionRequest {
    pub challenge: Option<Challenge>,
    pub token: Option<Vec<Token>>,
}

impl EndpointInfo for SessionRequest {
    fn get_info() -> Endpoint {
        Endpoint {
            path: "index.php/apps/passwords/api/1.0/session/request".into(),
            require_auth: true,
            method: Method::GET,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub salts: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Token {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionOpen {
    success: bool,
    #[serde(default)]
    keys: Option<HashMap<String, String>>,
}

impl EndpointInfo for SessionOpen {
    fn get_info() -> Endpoint {
        Endpoint {
            path: "index.php/apps/passwords/api/1.0/session/open".into(),
            require_auth: true,
            method: Method::POST,
        }
    }
}

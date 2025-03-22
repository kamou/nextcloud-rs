use crate::errors::NcError;

use log::info;
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{AUTHORIZATION, HeaderMap};
use serde::{Deserialize, Serialize};
use std::thread;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthData {
    #[serde(rename = "loginName")]
    login_name: String,

    #[serde(rename = "appPassword")]
    app_password: String,
}

#[derive(Deserialize, Debug)]
struct LoginResponse {
    poll: PollInfo,

    login: String,
}

#[derive(Deserialize, Debug)]
struct PollInfo {
    token: String,
    endpoint: String,
}

pub struct NextcloudClient {
    client: Client,
    server_url: Option<String>,
    headers: HeaderMap,
}

impl NextcloudClient {
    pub fn new(server_url: &str) -> Self {
        NextcloudClient {
            client: Client::new(),
            server_url: server_url.to_owned().into(),
            headers: HeaderMap::new(),
        }
    }
    pub fn server_url(&self) -> Result<&str, NcError> {
        self.server_url
            .as_deref()
            .ok_or(NcError::MissingField("server_url".into()))
    }

    pub fn post(&self, url: &str) -> RequestBuilder {
        self.client.post(url).headers(self.headers.clone())
    }

    pub fn get(&self, url: &str) -> RequestBuilder {
        self.client.get(url).headers(self.headers.clone())
    }

    fn verify_credentials(&self) -> Result<(), NcError> {
        let server_url = self.server_url()?;
        let check_url = format!("{}/ocs/v1.php/cloud/user?format=json", server_url);

        let response = self
            .get(&check_url)
            .header("OCS-APIREQUEST", "true")
            .send()?;

        match response.status().as_u16() {
            200 => Ok(()),
            _ => Err(NcError::AuthenticationFailed(response.status().as_u16())),
        }
    }

    pub fn login_from_auth_data(&mut self, auth_data: &AuthData) -> Result<(), NcError> {
        let credentials = format!("{}:{}", auth_data.login_name, auth_data.app_password);

        self.headers.insert(
            AUTHORIZATION,
            format!("Basic {}", base64::encode(credentials)).parse()?,
        );
        // verify that the credentials are valid, if they are not, remove the headers
        self.verify_credentials().inspect_err(|_| {
            self.headers.remove(AUTHORIZATION);
        })
    }

    pub fn login(&mut self) -> Result<AuthData, NcError> {
        let auth_data = self.perform_login_flow()?;
        let credentials = format!("{}:{}", auth_data.login_name, auth_data.app_password);
        let auth_header_value = format!("Basic {}", base64::encode(credentials));
        self.headers
            .insert(AUTHORIZATION, auth_header_value.parse()?);
        Ok(auth_data)
    }

    fn perform_login_flow(&mut self) -> Result<AuthData, NcError> {
        let server_url = self.server_url()?;

        let init_url = format!("{}/index.php/login/v2", server_url);

        let resp = self.post(&init_url).send()?;
        if !resp.status().is_success() {
            return Err(NcError::UnexpectedResponse {
                status: resp.status().as_u16(),
                body: "Unexpected status when initiating login flow".to_string(),
            });
        }

        // FIXME: I think this should be done by app, not by the library
        let login_response: LoginResponse = resp.json()?;
        if webbrowser::open(&login_response.login).is_err() {
            info!("Open the following URL in your browser to login:");
            info!("{}", login_response.login);
        }

        loop {
            let poll_resp = self
                .post(&login_response.poll.endpoint)
                .form(&[("token", &login_response.poll.token)])
                .send()?;

            if poll_resp.status().is_success() {
                let auth_data: AuthData = poll_resp.json()?;
                info!("Authentication successful!");
                return Ok(auth_data);
            }

            if poll_resp.status().as_u16() != 404 {
                return Err(NcError::UnexpectedResponse {
                    status: poll_resp.status().as_u16(),
                    body: "Failed to poll login status".to_string(),
                });
            }

            thread::sleep(Duration::from_secs(5));
        }
    }
}

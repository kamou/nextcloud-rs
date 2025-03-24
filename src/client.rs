use crate::errors::NcError;

use crate::endpoint::{Endpoint, EndpointInfo};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::sync::watch::Sender;
use tokio::time::{Duration, sleep};
use url::Url;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AuthData {
    #[serde(rename = "loginName")]
    login_name: String,

    #[serde(rename = "appPassword")]
    app_password: String,
}

#[derive(Clone, Deserialize, Debug)]
struct LoginResponse {
    poll: PollInfo,
    login: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
struct OcsMeta {
    status: String,
    statuscode: u16,
    message: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
struct OcsData<T> {
    data: Vec<T>,
    meta: OcsMeta,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
struct OcsResponse<T> {
    ocs: OcsData<T>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
struct UserStatus {
    #[serde(rename = "userId")]
    user_id: String,
    message: Option<String>,
    icon: Option<String>,
    #[serde(rename = "clearAt")]
    clear_at: Option<u16>,
    status: String,
}

#[derive(Clone, Deserialize, Debug)]
struct PollInfo {
    token: String,
    endpoint: String,
}

impl EndpointInfo for LoginResponse {
    fn get_info() -> Endpoint {
        Endpoint {
            path: "index.php/login/v2".into(),
            require_auth: false,
            method: Method::POST,
        }
    }
}

impl EndpointInfo for OcsResponse<UserStatus> {
    fn get_info() -> Endpoint {
        Endpoint {
            path: "ocs/v2.php/apps/user_status/api/v1/statuses?format=json".into(),
            require_auth: true,
            method: Method::GET,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NextcloudClient {
    client: Client,
    server_url: String,
    auth_data_tx: watch::Sender<Option<AuthData>>,
    auth_data_rx: watch::Receiver<Option<AuthData>>,
    auth_in_progress: bool,
}

async fn poll_authentication(
    req_client: Client,
    poll_info: PollInfo,
    auth_data_tx: Sender<Option<AuthData>>,
) -> Result<(), NcError> {
    let retry_delay = Duration::from_secs(1);
    loop {
        let resp = req_client
            .post(&poll_info.endpoint)
            .form(&[("token", &poll_info.token)])
            .send()
            .await?;

        if let Ok(auth_data) = resp.json::<AuthData>().await {
            auth_data_tx.send(Some(auth_data)).ok();
            return Ok(());
        }

        sleep(retry_delay).await;
    }
}

impl NextcloudClient {
    pub fn new(server_url: &str) -> Self {
        let (auth_data_tx, auth_data_rx) = watch::channel(None);
        NextcloudClient {
            client: Client::new(),
            server_url: server_url.to_owned(),
            auth_data_tx,
            auth_data_rx,
            auth_in_progress: false,
        }
    }

    pub async fn request<T>(&mut self, data: Option<String>) -> Result<T, NcError>
    where
        T: for<'de> Deserialize<'de> + EndpointInfo + Send,
    {
        let ep = T::get_info();
        let mut headers = HeaderMap::new();

        if ep.require_auth {
            self.wait_for_authentication(Duration::from_secs(60))
                .await?;
            let auth_data = self.auth_data_rx.borrow().clone().unwrap();
            let credentials = format!("{}:{}", auth_data.login_name, auth_data.app_password);
            let auth_str = format!("Basic {}", base64::encode(credentials))
                .parse()
                .unwrap();
            headers.insert(AUTHORIZATION, auth_str);
        }

        if ep.path.starts_with("ocs") {
            headers.insert("OCS-APIRequest", HeaderValue::from_static("true"));
        }

        let base = Url::parse(self.server_url()).unwrap();
        let url = base.join(&ep.path).unwrap().to_string();
        let mut req_builder = self.client.request(ep.method, url).headers(headers);
        if let Some(body) = data {
            req_builder = req_builder.body(body);
        }

        let response = req_builder.send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to parse response body".into());
            return Err(NcError::UnexpectedResponse { status, body });
        }

        Ok(response.json::<T>().await?)
    }

    pub fn server_url(&self) -> &str {
        self.server_url.as_str()
    }

    pub async fn verify_credentials(&mut self) -> Result<(), NcError> {
        let _: OcsResponse<UserStatus> = self.request(None).await?;
        Ok(())
    }

    pub async fn login_from_auth_data(&mut self, auth_data: &AuthData) -> Result<(), NcError> {
        self.auth_data_tx.send(Some(auth_data.clone())).unwrap(); // meh
        self.verify_credentials().await.inspect_err(|_| {
            self.auth_data_tx.send(None).unwrap();
        })?;

        self.auth_in_progress = false;
        Ok(())
    }

    pub async fn login(&mut self) -> Result<String, NcError> {
        let login_response: LoginResponse = self.request(None).await?;
        let poll_client = self.client.clone();
        self.auth_in_progress = true;

        let auth_data_tx = self.auth_data_tx.clone();
        tokio::spawn(async move {
            poll_authentication(poll_client, login_response.poll, auth_data_tx).await
        });

        Ok(login_response.login)
    }

    pub async fn wait_for_authentication(&mut self, timeout: Duration) -> Result<(), NcError> {
        use tokio::time::{self, Instant};

        let mut auth_data_rx = self.auth_data_rx.clone();

        if !self.auth_in_progress && auth_data_rx.borrow().is_none() {
            return Err(NcError::NotAuthenticated);
        }

        // quick check
        if auth_data_rx.borrow().is_some() {
            return Ok(());
        }

        let deadline = Instant::now() + timeout;

        loop {
            let remaining_time = deadline.saturating_duration_since(Instant::now());

            if remaining_time.is_zero() {
                return Err(NcError::TimedOut);
            }

            match time::timeout(remaining_time, auth_data_rx.changed()).await {
                Ok(Ok(_)) => {
                    if auth_data_rx.borrow().is_some() {
                        self.auth_in_progress = false;
                        return Ok(());
                    }
                    // ignore if not some
                }
                Ok(Err(err)) => return Err(NcError::ReceiverError(err)),
                Err(_) => return Err(NcError::TimedOut),
            }
        }
    }

    pub async fn get_auth_data(&self) -> Option<AuthData> {
        self.auth_data_rx.borrow().clone()
    }
}

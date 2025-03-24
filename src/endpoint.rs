use reqwest::Method;

pub struct Endpoint {
    pub path: String,
    pub require_auth: bool,
    pub method: Method,
}

pub trait EndpointInfo {
    fn get_info() -> Endpoint;
}

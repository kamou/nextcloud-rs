use crate::endpoint::{Endpoint, EndpointInfo};
use crate::passwords::fields::{ClearField, EncryptedField, EncryptedJson};
use reqwest::Method;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
enum CustomFieldType {
    #[serde(rename = "text")]
    Text, // Generic text value
    #[serde(rename = "secret")]
    Secret, // A secret value which should be treated like a password
    #[serde(rename = "email")]
    Email, // An email address
    #[serde(rename = "url")]
    Url, // A valid full url. Any protocol is allowed
    #[serde(rename = "file")]
    File, // The path to a file accessible over WebDav. The base url of the WebDav service is defined in the setting server.baseUrl.webdav
    #[serde(rename = "data")]
    Data, // A field with technical information. Should not be displayed to the user
}

#[allow(dead_code)]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct CustomField {
    label: String,
    #[serde(rename = "type")]
    type_: CustomFieldType,
    value: String,
}

impl EncryptedJson for CustomField {}
impl EncryptedJson for Vec<CustomField> {}

#[derive(Serialize, Deserialize, Debug)]
enum SecurityStatus {
    #[serde(rename = "0")]
    Good,
    #[serde(rename = "1")]
    Duplicate,
    #[serde(rename = "2")]
    Breached,
    #[serde(rename = "3")]
    NotChecked,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum StatusCode {
    #[serde(rename = "GOOD")]
    Good,
    #[serde(rename = "DUPLICATE")]
    Duplicate,
    #[serde(rename = "BREACHED")]
    Breached,
    #[serde(rename = "NOT_CHECKED")]
    NotChecked,
}

#[derive(Clone, Deserialize)]
pub struct Password {
    id: ClearField<String>,
    pub label: EncryptedField<String>,
    pub username: EncryptedField<String>,
    pub password: EncryptedField<String>,
    pub url: EncryptedField<String>,
    pub notes: EncryptedField<String>,
    #[serde(rename = "customFields")]
    pub custom_fields: Option<EncryptedField<Vec<CustomField>>>,
    pub status: ClearField<u32>,
    #[serde(rename = "statusCode")]
    pub status_code: ClearField<StatusCode>,
    pub hash: ClearField<String>,
    pub folder: ClearField<String>,
    pub revision: ClearField<String>,
    pub share: Option<ClearField<String>>,
    pub shared: ClearField<bool>,
    #[serde(rename = "cseType")]
    pub cse_type: ClearField<String>,
    #[serde(rename = "sseType")]
    pub sse_type: ClearField<String>,
    pub client: ClearField<String>,
    pub hidden: ClearField<bool>,
    pub trashed: ClearField<bool>,
    pub editable: ClearField<bool>,
    pub edited: ClearField<u64>,
    pub created: ClearField<u64>,
    pub updated: ClearField<u64>,
}

impl Password {
    pub fn id(&self) -> String {
        self.id.0.clone()
    }
}

impl EndpointInfo for Vec<Password> {
    fn get_info() -> Endpoint {
        Endpoint {
            path: "index.php/apps/passwords/api/1.0/password/list".into(),
            require_auth: true,
            method: Method::POST,
        }
    }
}

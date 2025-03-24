pub mod session;
use crate::client::NextcloudClient;
use crate::errors::NcError;
use crate::passwords::session::{SessionOpen, SessionRequest};
use reqwest::header::{HeaderMap, HeaderName};
use sodiumoxide::crypto::generichash;
use sodiumoxide::crypto::pwhash::argon2id13;
use std::collections::HashMap;

pub struct Passwords {
    client: NextcloudClient,
}

impl Passwords {
    pub fn new(client: &NextcloudClient) -> Passwords {
        Passwords {
            client: client.clone(),
        }
    }

    pub async fn session_open(&mut self, master_password: String) -> Result<(), NcError> {
        let challenge_data: SessionRequest = self.client.request(None).await?;
        if challenge_data.challenge.is_none() && challenge_data.token.is_none() {
            return Err(NcError::Generic(
            "No Master Password is set, get your shit together and please set a master password. Clear password store is not and will neer be supported.".into(),
        ));
        } else if challenge_data.challenge.is_none() {
            return Err(NcError::Generic("2FA not supported yet".into()));
        }

        let challenge_response = self
            .solve_pwdv1_challenge(master_password, &challenge_data.challenge.unwrap().salts)
            .await?;

        let mut form = HashMap::new();
        form.insert("challenge", challenge_response);
        let (_, headers): (SessionOpen, HeaderMap) =
            self.client.request_with_headers(Some(form)).await?;

        let api_session = headers
            .get("X-API-SESSION")
            .ok_or(NcError::MissingField("X-API-SESSION header".into()))?
            .to_str()?
            .to_owned();

        self.client
            .add_header("X-API-SESSION".parse::<HeaderName>()?, api_session.clone())
            .await?;

        Ok(())
    }

    async fn solve_pwdv1_challenge(
        &self,
        master_password: String,
        challenge: &[String],
    ) -> Result<String, NcError> {
        if challenge.len() != 3 {
            return Err(NcError::Generic("Invalid challenge".into()));
        }

        let password_salt = hex::decode(&challenge[0])?;
        let generic_hash_key = hex::decode(&challenge[1])?;
        let password_hash_salt = hex::decode(&challenge[2])?;

        if password_salt.len() != 256 {
            return Err(NcError::Generic("Invalid password salt length".into()));
        }

        if generic_hash_key.len() != 64 {
            return Err(NcError::Generic("Invalid generic hash key length".into()));
        }

        if password_hash_salt.len() != 16 {
            return Err(NcError::Generic("Invalid password hash salt length".into()));
        }

        let mut message = Vec::from(master_password.as_bytes());
        message.extend_from_slice(&password_salt);

        let generic_hash = generichash::hash(
            &message,
            Some(generichash::DIGEST_MAX),
            Some(&generic_hash_key),
        )
        .map_err(|_| NcError::Generic("Generic hash failed".into()))?;

        let mut derived_key = [0u8; 32];
        let argon_salt = argon2id13::Salt::from_slice(&password_hash_salt)
            .ok_or(NcError::Generic("Invalid salt2".into()))?;

        argon2id13::derive_key(
            &mut derived_key,
            generic_hash.as_ref(),
            &argon_salt,
            argon2id13::OPSLIMIT_INTERACTIVE,
            argon2id13::MEMLIMIT_INTERACTIVE,
        )
        .map_err(|_| NcError::Generic("Argon2id key derivation failed".into()))?;
        Ok(hex::encode(derived_key))
    }
}

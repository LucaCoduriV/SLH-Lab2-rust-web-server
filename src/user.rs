use crate::schema::*;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use axum_sessions::async_session::chrono;
use axum_sessions::async_session::chrono::Utc;
use strum_macros::{Display, EnumString};

#[derive(Debug, Display, EnumString, Serialize, Deserialize, PartialEq)]
pub enum AuthenticationMethod {
    Password,
    OAuth,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
pub struct User {
    pub email: String,
    auth_method: String,
    pub password: String,
    pub email_verified: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserDTO {
    pub email: String,
    pub auth_method: AuthenticationMethod,
    pub exp: usize,
}

impl User {
    pub fn new(
        email: &str,
        password: &str,
        auth_method: AuthenticationMethod,
        verified: bool,
    ) -> Self {
        Self {
            email: email.to_string(),
            auth_method: auth_method.to_string(),
            password: password.to_string(),
            email_verified: verified,
        }
    }

    pub fn get_auth_method(&self) -> AuthenticationMethod {
        AuthenticationMethod::from_str(&self.auth_method)
            .expect("Different auth method in enum and DB")
    }

    pub fn to_dto(&self) -> UserDTO {
        let expiration = Utc::now()
            .checked_add_signed(chrono::Duration::seconds(60))
            .expect("valid timestamp")
            .timestamp();

        UserDTO {
            email: self.email.clone(),
            auth_method: self.get_auth_method(),
            exp: expiration as usize,
        }
    }
}

use crate::db::Pool;
use crate::user::UserDTO;
use axum::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::response::Redirect;
use axum::RequestPartsExt;
use axum_extra::extract::CookieJar;
use jsonwebtoken::{DecodingKey, Validation};
use once_cell::sync::Lazy;

const REDIRECT_URL: &str = "/home";

static DECODING_KEY: Lazy<DecodingKey> = Lazy::new(|| DecodingKey::from_secret("secret".as_ref()));

/// Retrieves a UserDTO from request parts if a user is currently authenticated.
#[async_trait]
impl<S> FromRequestParts<S> for UserDTO
where
    Pool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Redirect;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let jar = parts
            .extract::<CookieJar>()
            .await.or(Err(Redirect::to(REDIRECT_URL)))?;

        let _jwt = jar.get("auth").ok_or(Redirect::to(REDIRECT_URL))?.value();

        if let Ok(token) = jsonwebtoken::decode::<UserDTO>(&_jwt, &DECODING_KEY,
                                                           &Validation::default()){
            return Ok(token.claims);
        }

        Err(Redirect::to(REDIRECT_URL))
    }
}

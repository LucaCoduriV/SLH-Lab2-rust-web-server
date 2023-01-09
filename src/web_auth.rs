use std::collections::HashMap;
use crate::db::{DbConn, get_user, save_user, update_password, user_exists, validate_account};
use crate::models::{
    AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest,
};
use crate::user::{AuthenticationMethod, User, UserDTO};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_sessions::async_session::{MemoryStore, Session, SessionStore};
use serde_json::json;
use std::error::Error;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use jsonwebtoken::{encode, EncodingKey, Header};

use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope};
use oauth2::reqwest::{async_http_client};
use crate::mail::send_verification_email;
use crate::oauth::get_google_oauth_email;
use rand::distributions::DistString;
use time::{Duration, OffsetDateTime};
use zxcvbn::zxcvbn;

static MIN_PASSWORD_SCORE: u8 = 3;
static MIN_PASSWORD_LEN: usize = 8;
static MAX_PASSWORD_LEN: usize = 64;

/// Declares the different endpoints
/// state is used to pass common structs to the endpoints
pub fn stage(state: AppState) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/oauth/google", get(google_oauth))
        .route("/_oauth", get(oauth_redirect))
        .route("/password_update", post(password_update))
        .route("/logout", get(logout))
        .route("/verify-email/:token", get(verify_email))
        .with_state(state)
}

/// Endpoint handling login
/// POST /login
/// BODY { "login_email": "email", "login_password": "password" }
async fn login(
    mut _conn: DbConn,
    jar: CookieJar,
    Json(login): Json<LoginRequest>,
) -> Result<(CookieJar, AuthResult), Response> {
    let _email = login.login_email;
    let _password = login.login_password;

    if let Ok(user) = get_user(&mut _conn, _email.as_str()) {
        if !user.email_verified {
            return Err(AuthResult::NotVerified.into_response());
        }

        if user.get_auth_method() == AuthenticationMethod::Password {
            let parsed_hash = PasswordHash::new(&user.password.as_str()).unwrap();
            if let Ok(_) = Argon2::default().verify_password(_password.as_bytes(), &parsed_hash) {
                println!("User logged in !");
                // Once the user has been created, authenticate the user by adding a JWT cookie in the cookie jar
                let jar = add_auth_cookie(jar, &user.to_dto())
                    .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
                return Ok((jar, AuthResult::Success));
            }
        }
    }
    println!("User does not exist !");
    Err(AuthResult::Error.into_response())
}

/// Endpoint used to register a new account
/// POST /register
/// BODY { "register_email": "email", "register_password": "password", "register_password2": "password" }
async fn register(
    mut _conn: DbConn,
    State(_session_store): State<MemoryStore>,
    Json(register): Json<RegisterRequest>,
) -> Result<AuthResult, Response> {
    let _email = register.register_email;
    let _password = register.register_password;

    if _password.chars().count() < MIN_PASSWORD_LEN || _password.chars().count() > MAX_PASSWORD_LEN {
        return Err(AuthResult::Error.into_response());
    }

    let estimate = zxcvbn(_password.as_str(), &[_email.as_str()]).unwrap();
    if estimate.score() < MIN_PASSWORD_SCORE {
        return Err(AuthResult::Error.into_response());
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(_password.as_bytes(), &salt).unwrap().to_string();

    if let Ok(_) = user_exists(&mut _conn, _email.as_str()) {
        return Err(AuthResult::Error.into_response());
    }

    save_user(&mut _conn, User::new(_email.as_str(), hash.as_str(),
                                    AuthenticationMethod::Password, false))
        .or(Err(AuthResult::Error.into_response()))?;
    println!("User created !");

    let mut session = Session::new();
    session.insert("email", _email.clone()).or(Err(AuthResult::Error.into_response()))?;

    let session_id = match _session_store.store_session(session).await {
        Ok(Some(value)) => value,
        _ => return Err(AuthResult::Error.into_response()),
    };

    send_verification_email(
        _email.clone(),
        format!("http://localhost:8000/verify-email/{}", urlencoding::encode(session_id.as_str()))
            .to_string(),
    );

    Ok(AuthResult::Success)
}

async fn verify_email(Path(params): Path<HashMap<String, String>>, mut _conn: DbConn, State(_session_store): State<MemoryStore>) ->
Result<Redirect, StatusCode> {
    let session_id = urlencoding::decode(params.get("token").unwrap()).unwrap().into_owned();

    let session = match _session_store.load_session(session_id.clone()).await {
        Ok(Some(value)) => value,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let email: Option<String> = session.get("email");

    if email.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    validate_account(&mut _conn, email.unwrap().as_str());

    _session_store.destroy_session(session);

    Ok(Redirect::to("/login"))
}

/// Endpoint used for the first OAuth step
/// GET /oauth/google
async fn google_oauth(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let client = &crate::oauth::OAUTH_CLIENT;

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    let now = OffsetDateTime::now_utc();
    let one_hour = Duration::hours(1);

    let cookie_csrf_token = Cookie::build("csrf_token", csrf_token.secret().to_string())
        .path("/")
        .secure(true)
        .http_only(true)
        .expires(now + one_hour)
        .finish();
    let jar = jar.add(cookie_csrf_token);

    let mut session = Session::new();
    session.insert("pkce_verifier", pkce_verifier).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    session.insert("csrf_token", csrf_token).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    let session_id = _session_store.store_session(session).await.unwrap().unwrap();



    let cookie = Cookie::build("session_id", session_id)
        .path("/")
        .secure(true)
        .http_only(true)
        .expires(now + one_hour)
        .finish();
    let jar = jar.add(cookie);


    Ok((jar, Redirect::to(auth_url.as_str())))
}

/// Endpoint called after a successful OAuth login.
/// GET /_oauth?state=x&code=y
async fn oauth_redirect(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
    mut _conn: DbConn,
    _params: Query<OAuthRedirect>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let cookie = jar.get("session_id").ok_or(StatusCode::BAD_REQUEST)?;

    let session = match _session_store.load_session(cookie.value().to_string()).await {
        Ok(Some(value)) => value,
        _ => return Err(StatusCode::BAD_REQUEST)
    };


    let pkce_verifier: PkceCodeVerifier = session.get("pkce_verifier").ok_or(StatusCode::BAD_REQUEST)?;

    let csrf_token: CsrfToken = session.get("csrf_token").ok_or(StatusCode::BAD_REQUEST)?;

    let cookie_csrf_token = jar.get("csrf_token").ok_or(StatusCode::BAD_REQUEST)?.clone();


    if csrf_token.secret() != cookie_csrf_token.value() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token_result =
        crate::oauth::OAUTH_CLIENT
            .exchange_code(AuthorizationCode::new(_params.code.to_string()))
            .set_pkce_verifier(pkce_verifier)
            .request_async(async_http_client).await.or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let email = get_google_oauth_email(&token_result).await.or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let jar = if let Ok(user) = get_user(&mut _conn, email.as_str()) {
        if user.get_auth_method() == AuthenticationMethod::Password {
            return Err(StatusCode::UNAUTHORIZED);
        }
        add_auth_cookie(jar, &user.to_dto())
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
    } else {
        let user = User::new(email.as_str(), "", AuthenticationMethod::OAuth, true);
        let user_dto = &user.to_dto();
        save_user(&mut _conn, user).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
        add_auth_cookie(jar, user_dto)
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
    };

    let jar = jar.remove(cookie_csrf_token);
    // session.remove("csrf_token"); je pense qu'il est possible d'empêcher quelqu'un de se connecter avec cette ligne
    Ok((jar, Redirect::to("/home")))
}

/// Endpoint handling login
/// POST /password_update
/// BODY { "old_password": "pass", "new_password": "pass" }
async fn password_update(
    mut _conn: DbConn,
    _user: UserDTO,
    Json(_update): Json<PasswordUpdateRequest>,
) -> Result<AuthResult, Response> {
    let user = get_user(&mut _conn, _user.email.as_str())
        .or(Err((StatusCode::BAD_REQUEST, AuthResult::Error).into_response()))?;

    if user.get_auth_method() == AuthenticationMethod::OAuth {
        return Err((StatusCode::BAD_REQUEST, AuthResult::Error).into_response());
    }

    let parsed_hash = PasswordHash::new(&user.password.as_str()).unwrap();

    if Argon2::default().verify_password(_update.old_password.as_bytes(), &parsed_hash).is_err() {
        return Err((StatusCode::BAD_REQUEST, AuthResult::Error).into_response());
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(_update.new_password.as_bytes(), &salt).unwrap().to_string();

    update_password(&mut _conn, _user.email.as_str(), hash.as_str())
        .or(Err((StatusCode::INTERNAL_SERVER_ERROR, AuthResult::Success).into_response()))?;

    Ok(AuthResult::Success)
}

/// Endpoint handling the logout logic
/// GET /logout
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let new_jar = jar.remove(Cookie::named("auth"));
    (new_jar, Redirect::to("/home"))
}

#[allow(dead_code)]
fn add_auth_cookie(jar: CookieJar, _user: &UserDTO) -> Result<CookieJar, Box<dyn Error>> {
    // Il faudrait peut-être ajouter un lifetime au cookie.

    let now = OffsetDateTime::now_utc();
    let one_week = Duration::weeks(1);

    let token = encode(&Header::default(), _user, &EncodingKey::from_secret("secret".as_ref()))?;
    Ok(jar.add(Cookie::build("auth", token).path("/")
        .secure(true)
        .http_only(true)
        .expires(now + one_week)
        .finish()))
}

enum AuthResult {
    Success,
    Error,
    NotVerified,
}

/// Returns a status code and a JSON payload based on the value of the enum
impl IntoResponse for AuthResult {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Success => (StatusCode::OK, "Success"),
            Self::Error => (StatusCode::UNAUTHORIZED, "Error"),
            Self::NotVerified => (StatusCode::UNAUTHORIZED, "Account not verified"),
        };
        (status, Json(json!({ "res": message }))).into_response()
    }
}

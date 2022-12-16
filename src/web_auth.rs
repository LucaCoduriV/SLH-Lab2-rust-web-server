use std::borrow::BorrowMut;
use crate::db::{DbConn, get_user, save_user, user_exists};
use crate::models::{
    AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest,
};
use crate::user::{AuthenticationMethod, User, UserDTO};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_sessions::async_session::{MemoryStore, Session, SessionStore};
use serde_json::json;
use std::error::Error;
use std::str::FromStr;
use axum::body::BoxBody;
use jsonwebtoken::{encode, EncodingKey, Header};

use oauth2::{AuthorizationCode, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl};
use oauth2::basic::BasicClient;
use oauth2::reqwest::{async_http_client, http_client};
use crate::oauth::get_google_oauth_email;
use crate::schema::users::password;

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
    // TODO: Implement the login function. You can use the functions inside db.rs to check if
    //       the user exists and get the user info.
    let _email = login.login_email;
    let _password = login.login_password;

    if let Ok(user) = get_user(&mut _conn, _email.as_str()) {
        if user.get_auth_method() == AuthenticationMethod::Password {
            if let Ok(true) = argon2::verify_encoded(user.password.as_str(), _password.as_bytes()) {
                println!("User logged in !");
                // Once the user has been created, authenticate the user by adding a JWT cookie in the cookie jar
                let jar = add_auth_cookie(jar, &user.to_dto())
                    .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
                return Ok((jar, AuthResult::Success));
            }
        }
    }
    println!("User does not exist !");
    Ok((jar, AuthResult::Error))
}

/// Endpoint used to register a new account
/// POST /register
/// BODY { "register_email": "email", "register_password": "password", "register_password2": "password" }
async fn register(
    mut _conn: DbConn,
    State(_session_store): State<MemoryStore>,
    Json(register): Json<RegisterRequest>,
) -> Result<AuthResult, Response> {
    // TODO: Implement the register function. The email must be verified by sending a link.
    //       You can use the functions inside db.rs to add a new user to the DB.
    let _email = register.register_email;
    let _password = register.register_password;

    let salt = b"randomsalt"; // TODO create random salt
    let config = argon2::Config::default();
    let hash = argon2::hash_encoded(_password.as_bytes(), salt, &config).unwrap();

    if let Err(_) = user_exists(&mut _conn, _email.as_str()) {
        save_user(&mut _conn, User::new(_email.as_str(), hash.as_str(), AuthenticationMethod::Password, true));
        println!("User created !");
        Ok(AuthResult::Success)
    } else {
        // create a wrong insert to db
        println!("User already exists");
        Ok(AuthResult::Error)
    }

    // Once the user has been created, send a verification link by email
    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.
}

// TODO: Create the endpoint for the email verification function.

/// Endpoint used for the first OAuth step
/// GET /oauth/google
async fn google_oauth(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // TODO: This function is used to authenticate a user with Google's OAuth2 service.
    //       We want to use a PKCE authentication flow, you will have to generate a
    //       random challenge and a CSRF token. In order to get the email address of
    //       the user, use the following scope: https://www.googleapis.com/auth/userinfo.email
    //       Use Redirect::to(url) to redirect the user to Google's authentication form.

    // let client = crate::oauth::OAUTH_CLIENT.todo();

    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.

    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
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

    let cookie_csrf_token = Cookie::build("csrf_token", csrf_token.secret().to_string())
        .path("/")
        .secure(true)
        .http_only(true)
        .finish();
    let jar = jar.add(cookie_csrf_token);

    let mut session = Session::new();
    session.insert("pkce_verifier", pkce_verifier).expect("Session couldn't insert pkce_verifier");
    session.insert("csrf_token", csrf_token).expect("Session couldn't insert pkce_verifier");
    let session_id = _session_store.store_session(session).await.unwrap().unwrap();

    let cookie = Cookie::build("session_id", session_id)
        .path("/")
        .secure(true)
        .http_only(true)
        .finish();
    let jar = jar.add(cookie);
    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.

    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.


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

    let cookie_csrf_token = jar.get("csrf_token").ok_or(StatusCode::BAD_REQUEST)?;

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

    // Once the OAuth user is authenticated, create the user in the DB and add a JWT cookie
    // let jar = add_auth_cookie(jar, &user_dto).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok((jar, Redirect::to("/home")))
}

/// Endpoint handling login
/// POST /password_update
/// BODY { "old_password": "pass", "new_password": "pass" }
async fn password_update(
    _conn: DbConn,
    _user: UserDTO,
    Json(_update): Json<PasswordUpdateRequest>,
) -> Result<AuthResult, Response> {
    // TODO: Implement the password update function.
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
    // TODO: You have to create a new signed JWT and store it in the auth cookie.
    //       Careful with the cookie options.
    let token = encode(&Header::default(), _user, &EncodingKey::from_secret("secret".as_ref()))?;
    Ok(jar.add(Cookie::build("auth", token).finish()))
}

enum AuthResult {
    Success,
    Error,
}

/// Returns a status code and a JSON payload based on the value of the enum
impl IntoResponse for AuthResult {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Success => (StatusCode::OK, "Success"),
            Self::Error => (StatusCode::UNAUTHORIZED, "Error"),
        };
        (status, Json(json!({ "res": message }))).into_response()
    }
}

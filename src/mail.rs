use std::env;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use once_cell::sync::Lazy;
use regex::Regex;


#[test]
fn test_send_email() {
    extern crate dotenv;
    use dotenv::dotenv;

    dotenv().ok();
    send_verification_email("test@gmail.com".to_string(),
                            "http://localhost:8080/verify-account?token=alksdhajsdsaslj".to_string
    ());
}

#[test]
fn test_is_email_valid(){
    let valid_email_addresses = [
        "foo@bar.com",
        "foo.bar42@c.com",
        "42@c.com",
        "f@42.co",
        "foo@4-2.team",
        "foo_bar@bar.com",
        "_bar@bar.com",
        "foo_@bar.com",
        "foo+bar@bar.com",
        "+bar@bar.com",
        "foo+@bar.com",
        "foo.lastname@bar.com"
    ];

    let invalid_email_addresses = [
    "#@%^%#$@#$@#.com",
    "@example.com",
    "Joe Smith <email@example.com>",
        "email.example.com",
    "email@example@example.com",
        ".email@example.com",
    "email.@example.com",
    "あいうえお@example.com",
    "email@example.com (Joe Smith)",
    "email@example",
    "email@-example.com",
    "email@111.222.333.44444",
    "email@example..com",
    "Abc..123@example.com"
    ];

    for email in valid_email_addresses.iter() {
        assert!(is_email_valid(email));
    }

    for email in invalid_email_addresses.iter() {
        assert!(!is_email_valid(email));
    }
}

pub fn is_email_valid(email: &str) -> bool{
    static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})$").unwrap()
    });

    EMAIL_REGEX.is_match(email)
}

pub fn send_verification_email(other_email: String, activation_link: String) {
    let host = env::var("SMTP_HOST").expect("Could not get SMTP_HOST from ENV");
    let port = env::var("SMTP_PORT").expect("Could not get SMTP_PORT from ENV").parse::<u16>()
        .expect("Port should be a number.");
    let username = env::var("SMTP_USERNAME").expect("Could not get SMTP_USERNAME from ENV");
    let password = env::var("SMTP_PASSWORD").expect("Could not get SMTP_PASSWORD from ENV");

    let email = Message::builder()
        .from("MyCoolWebSite <admin@myCoolwebsite.tld>".parse().unwrap())
        .to(format!("{} <{}>", other_email.split("@").collect::<Vec<_>>()[0], other_email)
            .parse()
            .unwrap())
        .subject("Email verification")
        .body(format!("Here is your link to verify your subscription: {}", activation_link))
        .unwrap();

    let creds = Credentials::new(username, password);

// Open a remote connection to gmail
    let mailer = SmtpTransport::builder_dangerous(host.as_str())
        .credentials(creds)
        .port(port)
        .build();

// Send the email
    match mailer.send(&email) {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => panic!("Could not send email: {:?}", e),
    }
}
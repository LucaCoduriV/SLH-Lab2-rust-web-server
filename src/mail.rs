use std::env;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};


#[test]
fn test_send_email() {
    extern crate dotenv;
    use dotenv::dotenv;

    dotenv().ok();
    send_verification_email("test@gmail.com".to_string(),
                            "http://localhost:8080/verify-account?token=alksdhajsdsaslj".to_string
    ());
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
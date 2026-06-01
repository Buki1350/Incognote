use lettre::{
    message::Mailbox,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

#[derive(Clone)]
pub struct EmailService {
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    mail_from: Mailbox,
    app_base_url: String,
}

impl EmailService {
    pub fn from_env() -> Self {
        let mail_from: Mailbox = std::env::var("MAIL_FROM")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| "Incognote <no-reply@incognote.local>".parse().unwrap());

        let app_base_url = std::env::var("APP_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        let smtp_host = match std::env::var("SMTP_HOST") {
            Ok(host) => host,
            Err(_) => {
                tracing::warn!("SMTP_HOST not set; email sending disabled");
                return Self { transport: None, mail_from, app_base_url };
            }
        };

        let smtp_port = std::env::var("SMTP_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(587);

        let smtp_user = std::env::var("SMTP_USER");
        let smtp_pass = std::env::var("SMTP_PASS");

        let transport = match (smtp_user, smtp_pass) {
            (Ok(user), Ok(pass)) => {
                if is_placeholder(&user) || is_placeholder(&pass) {
                    tracing::warn!("SMTP_USER or SMTP_PASS appears to be a placeholder; email sending disabled");
                    None
                } else {
                    let creds = Credentials::new(user, pass);
                    match AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp_host) {
                        Ok(relay) => Some(relay.credentials(creds).port(smtp_port).build()),
                        Err(e) => {
                            tracing::warn!(%smtp_host, error = %e, "failed to build SMTP relay; using localhost fallback");
                            Some(
                                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp_host)
                                    .port(smtp_port)
                                    .credentials(creds)
                                    .build(),
                            )
                        }
                    }
                }
            }
            _ => {
                tracing::warn!("SMTP_USER or SMTP_PASS not set; trying anonymous relay");
                match AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp_host) {
                    Ok(relay) => Some(relay.port(smtp_port).build()),
                    Err(e) => {
                        tracing::warn!(%smtp_host, error = %e, "failed to build SMTP relay; email disabled");
                        None
                    }
                }
            }
        };

        Self { transport, mail_from, app_base_url }
    }

    pub fn is_enabled(&self) -> bool {
        self.transport.is_some()
    }

    pub async fn send_verification_email(&self, to_email: &str, token: &str) -> Result<(), String> {
        let subject = "Verify your Incognote email address";
        let body = format!(
            "Welcome to Incognote!\n\n\
             Please verify your email address by clicking the link below:\n\n\
             {base}/verify-email?email={email}&token={token}\n\n\
             Or enter this token in the app:\n{token}\n\n\
             This token expires in 24 hours.",
            base = self.app_base_url,
            email = urlencoding(to_email),
            token = token,
        );

        self.send_email(to_email, subject, &body).await
    }

    pub async fn send_password_reset_email(&self, to_email: &str, token: &str) -> Result<(), String> {
        let subject = "Reset your Incognote password";
        let body = format!(
            "You requested a password reset for Incognote.\n\n\
             Click the link below to reset your password:\n\n\
             {base}/reset-password?email={email}&token={token}\n\n\
             Or enter this token in the app:\n{token}\n\n\
             This link expires in 1 hour.\n\n\
             If you didn't request this, you can safely ignore this email.",
            base = self.app_base_url,
            email = urlencoding(to_email),
            token = token,
        );

        self.send_email(to_email, subject, &body).await
    }

    async fn send_email(&self, to_email: &str, subject: &str, body: &str) -> Result<(), String> {
        let transport = self.transport.as_ref().ok_or_else(|| {
            "SMTP not configured; cannot send email".to_string()
        })?;

        let to_mailbox: Mailbox = to_email
            .parse()
            .map_err(|e| format!("invalid recipient email: {e}"))?;

        let message = Message::builder()
            .from(self.mail_from.clone())
            .to(to_mailbox)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| format!("failed to build email: {e}"))?;

        transport.send(message).await.map_err(|e| {
            tracing::error!(%to_email, %subject, error = %e, "failed to send email");
            format!("failed to send email: {e}")
        })?;

        tracing::info!(%to_email, %subject, "email sent");
        Ok(())
    }
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    lower.contains("your-") || lower.contains("placeholder") || lower.contains("change_this")
        || lower == "your-app-password" || lower == "your-email@gmail.com"
}

fn urlencoding(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

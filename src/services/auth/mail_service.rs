use crate::app::AppError;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};

#[derive(Clone)]
pub struct MailService {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    app_base_url: String,
}

impl MailService {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let smtp_host = std::env::var("SMTP_HOST").unwrap_or_else(|_| "localhost".to_string());
        let smtp_port = std::env::var("SMTP_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(1025);

        let smtp_user = std::env::var("SMTP_USER").ok();
        let smtp_pass = std::env::var("SMTP_PASS").ok();

        let from = std::env::var("MAIL_FROM")
            .unwrap_or_else(|_| "no-reply@rust-backend-template.local".to_string())
            .parse::<Mailbox>()?;

        let app_base_url =
            std::env::var("APP_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

        let mut transport_builder =
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(smtp_host).port(smtp_port);

        if let (Some(username), Some(password)) = (smtp_user, smtp_pass) {
            transport_builder = transport_builder.credentials(Credentials::new(username, password));
        }

        Ok(Self {
            mailer: transport_builder.build(),
            from,
            app_base_url,
        })
    }

    pub async fn send_verification_email(&self, to: &str, token: &str) -> Result<(), AppError> {
        let recipient = to
            .parse::<Mailbox>()
            .map_err(|_| AppError::Validation(format!("incorrect email ({})", to)))?;

        let verify_url = format!(
            "{}/verify-email?token={}",
            self.app_base_url.trim_end_matches('/'),
            token
        );

        let message = Message::builder()
            .from(self.from.clone())
            .to(recipient)
            .subject("Verify your e-mail")
            .body(format!(
                "Click the link to verify your account:\n{verify_url}\n\nThe link expires in 24 hours."
            ))
            .map_err(|_| AppError::Internal("failed to build verification e-mail".to_string()))?;

        self.mailer.send(message).await.map_err(|error| {
            AppError::Internal(format!("failed to send verification e-mail: {error}"))
        })?;

        Ok(())
    }
}

import os
from datetime import datetime, timedelta, timezone
from typing import List

import jwt
from fastapi import HTTPException
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from jinja2 import Template

from app.core.config import settings

# Email configuration
conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_FROM_NAME=settings.MAIL_FROM_NAME,
    MAIL_STARTTLS=settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=settings.USE_CREDENTIALS,
    VALIDATE_CERTS=settings.VALIDATE_CERTS
)

# Email verification token settings
EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS = 24
SECRET_KEY = "f4b3e6b7b24b3b7f3f6b7b4"  # Should match the one in auth.py
ALGORITHM = "HS256"


def create_email_verification_token(email: str) -> str:
    """Create a token for email verification"""
    expire = datetime.now(timezone.utc) + timedelta(hours=EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    to_encode = {"sub": email, "exp": expire, "type": "email_verification"}
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token


def verify_email_verification_token(token: str) -> str:
    """Verify the email verification token and return the email"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")

        if email is None or token_type != "email_verification":
            raise HTTPException(status_code=400, detail="Token inválido")

        return email
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token expirado")
    except jwt.DecodeError:
        raise HTTPException(status_code=400, detail="Token inválido")


def get_verification_email_template() -> str:
    """Get the email verification template"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Verificación de Email</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                background-color: #007bff;
                color: white;
                padding: 20px;
                text-align: center;
                border-radius: 5px 5px 0 0;
            }
            .content {
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 0 0 5px 5px;
            }
            .button {
                display: inline-block;
                background-color: #28a745;
                color: white;
                padding: 12px 24px;
                text-decoration: none;
                border-radius: 5px;
                margin: 20px 0;
            }
            .footer {
                margin-top: 20px;
                padding-top: 20px;
                border-top: 1px solid #dee2e6;
                color: #6c757d;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>{{ project_name }}</h1>
        </div>
        <div class="content">
            <h2>¡Bienvenido/a {{ first_name }}!</h2>
            <p>Gracias por registrarte en nuestro sistema. Para completar tu registro, necesitas verificar tu dirección de email.</p>
            <p>Haz clic en el siguiente botón para verificar tu cuenta:</p>
            <a href="{{ verification_url }}" class="button">Verificar Email</a>
            <p>Si no puedes hacer clic en el botón, copia y pega el siguiente enlace en tu navegador:</p>
            <p><a href="{{ verification_url }}">{{ verification_url }}</a></p>
            <div class="footer">
                <p>Este enlace expirará en 24 horas.</p>
                <p>Si no te registraste en nuestro sistema, puedes ignorar este email.</p>
            </div>
        </div>
    </body>
    </html>
    """


async def send_verification_email(email: str, first_name: str) -> bool:
    """Send verification email to user"""
    try:
        # Create verification token
        token = create_email_verification_token(email)
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"

        # Prepare email template
        template = Template(get_verification_email_template())
        html_content = template.render(
            project_name=settings.PROJECT_NAME,
            first_name=first_name,
            verification_url=verification_url
        )

        # Create message
        message = MessageSchema(
            subject="Verificación de Email - " + settings.PROJECT_NAME,
            recipients=[email],
            body=html_content,
            subtype=MessageType.html
        )

        # Send email
        fm = FastMail(conf)
        await fm.send_message(message)

        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


async def send_password_reset_email(email: str, first_name: str, reset_token: str) -> bool:
    """Send password reset email to user"""
    try:
        reset_url = f"{settings.FRONTEND_URL}/auth/reset-password?token={reset_token}"

        template = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Restablecer Contraseña</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .header {
                    background-color: #dc3545;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }
                .content {
                    background-color: #f8f9fa;
                    padding: 20px;
                    border-radius: 0 0 5px 5px;
                }
                .button {
                    display: inline-block;
                    background-color: #dc3545;
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 20px 0;
                }
                .footer {
                    margin-top: 20px;
                    padding-top: 20px;
                    border-top: 1px solid #dee2e6;
                    color: #6c757d;
                    font-size: 14px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ project_name }}</h1>
            </div>
            <div class="content">
                <h2>Restablecer Contraseña</h2>
                <p>Hola {{ first_name }},</p>
                <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta.</p>
                <p>Haz clic en el siguiente botón para restablecer tu contraseña:</p>
                <a href="{{ reset_url }}" class="button">Restablecer Contraseña</a>
                <p>Si no puedes hacer clic en el botón, copia y pega el siguiente enlace en tu navegador:</p>
                <p><a href="{{ reset_url }}">{{ reset_url }}</a></p>
                <div class="footer">
                    <p>Este enlace expirará en 1 hora.</p>
                    <p>Si no solicitaste restablecer tu contraseña, puedes ignorar este email.</p>
                </div>
            </div>
        </body>
        </html>
        """)

        html_content = template.render(
            project_name=settings.PROJECT_NAME,
            first_name=first_name,
            reset_url=reset_url
        )

        message = MessageSchema(
            subject="Restablecer Contraseña - " + settings.PROJECT_NAME,
            recipients=[email],
            body=html_content,
            subtype=MessageType.html
        )

        fm = FastMail(conf)
        await fm.send_message(message)

        return True
    except Exception as e:
        print(f"Error sending password reset email: {e}")
        return False

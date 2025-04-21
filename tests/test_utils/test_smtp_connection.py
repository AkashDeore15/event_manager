# tests/test_utils/test_smtp_connection.py
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app.utils.smtp_connection import SMTPClient

@pytest.mark.asyncio
async def test_send_email_success():
    """Test successful email sending through SMTP."""
    # Create SMTP client instance
    smtp_client = SMTPClient(
        server="test.server.com",
        port=587,
        username="test@example.com",
        password="password123"
    )
    
    # Mock SMTP connection
    mock_smtp = MagicMock()
    mock_smtp.__enter__.return_value = mock_smtp
    
    # Patch smtplib.SMTP to return our mock
    with patch('smtplib.SMTP', return_value=mock_smtp):
        # Test sending an email
        await smtp_client.send_email(
            subject="Test Subject",
            html_content="<p>Test Content</p>",
            recipient="recipient@example.com"
        )
        
        # Assert SMTP methods were called correctly
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("test@example.com", "password123")
        mock_smtp.sendmail.assert_called_once()
        
        # Verify sendmail arguments
        sendmail_args = mock_smtp.sendmail.call_args[0]
        assert sendmail_args[0] == "test@example.com"  # From address
        assert sendmail_args[1] == "recipient@example.com"  # To address
        assert "Test Subject" in sendmail_args[2]  # Subject in email content

@pytest.mark.asyncio
async def test_send_email_exception():
    """Test SMTP exception handling during email sending."""
    # Create SMTP client instance
    smtp_client = SMTPClient(
        server="test.server.com",
        port=587,
        username="test@example.com",
        password="password123"
    )
    
    # Mock SMTP to raise an exception
    mock_smtp = MagicMock()
    mock_smtp.__enter__.side_effect = Exception("SMTP connection error")
    
    # Patch smtplib.SMTP and logging
    with patch('smtplib.SMTP', return_value=mock_smtp), \
         patch('logging.error') as mock_logging_error:
        
        # Test sending an email that will fail
        with pytest.raises(Exception):
            await smtp_client.send_email(
                subject="Test Subject",
                html_content="<p>Test Content</p>",
                recipient="recipient@example.com"
            )
        
        # Verify error is logged
        mock_logging_error.assert_called_once()
        assert "Failed to send email" in mock_logging_error.call_args[0][0]
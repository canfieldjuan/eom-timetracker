import email_service
from email_service import EmailService


def test_email_configuration_rejects_placeholders_without_network(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("configuration validation must not send a probe email")

    monkeypatch.setattr(email_service.requests, "post", fail_if_called)

    service = EmailService(
        {
            "resend_api_key": "your_resend_api_key_here",
            "from_email": "reports@yourcompany.com",
        }
    )

    assert service.test_email_configuration() is False


def test_email_configuration_accepts_complete_values_without_network(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("configuration validation must not send a probe email")

    monkeypatch.setattr(email_service.requests, "post", fail_if_called)

    service = EmailService(
        {
            "resend_api_key": "configured-test-key",
            "from_email": "reports@effinghamofficemaids.com",
        }
    )

    assert service.test_email_configuration() is True

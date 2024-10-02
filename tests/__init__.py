# email_processor/__init__.py
from email_processor.email_processor import EmailProcessor
from email_processor.utils import extract_ip_from_received, extract_urls
from email_processor.PhishingEmail import PhishingEmail

__all__ = ['EmailProcessor', 'extract_ip_from_received', 'extract_urls', 'PhishingEmail']

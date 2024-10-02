# email_processor/__init__.py
from .email_processor import EmailProcessor
from .utils import extract_ip_from_received, extract_urls
from .PhishingEmail import PhishingEmail

__all__ = ['EmailProcessor', 'extract_ip_from_received', 'extract_urls', 'PhishingEmail']

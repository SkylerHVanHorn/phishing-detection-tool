import unittest
from email_processor.email_processor import EmailProcessor
from email_processor.utils import extract_ip_from_received, extract_urls
from email_processor.email_processor import EmailProcessor
from email_processor.utils import extract_ip_from_received, extract_urls
from email_processor.PhishingEmail import PhishingEmail

class TestEmailProcessor(unittest.TestCase):

    def setUp(self):
        self.processor = EmailProcessor()
        self.processor.safe_domains = ['safe.com']
        self.processor.keywords = ['urgent', 'click here', 'verify your account']

    def test_empty_email_list(self):
        # Test handling of an empty email list
        self.processor.emails = []
        report = self.processor.generate_report()
        self.assertIn("Total Emails Scanned: 0", report)
        self.assertIn("No suspicious or malicious emails were detected", report)

    def test_email_missing_fields(self):
        # Test emails with missing fields like subject or body
        incomplete_email = {
            'sender': 'unknown@untrustworthy.com',
            'recipient': 'user@example.com',
            'headers': {'Received': 'from 123.456.789.012'},
            'timestamp': '2024-09-30T12:34:56'
        }
        self.processor.emails = [incomplete_email]
        report = self.processor.generate_report()
        self.assertIn("Total Emails Scanned: 1", report)

    def test_trusted_domain_with_malicious_content(self):
        # Test email from a trusted domain but with malicious content
        trusted_malicious_email = {
            'sender': 'trusted@safe.com',
            'recipient': 'user@example.com',
            'subject': 'urgent action required',
            'body': 'This is an important message. click here to verify your account.',
            'headers': {'Received': 'from 123.456.789.012'},
            'timestamp': '2024-09-30T12:34:56'
        }
        self.processor.emails = [trusted_malicious_email]
        report = self.processor.generate_report()

        # The email is from a trusted domain, so it should not be classified as suspicious or malicious
        self.assertIn("No suspicious or malicious emails were detected.", report)

    def test_email_without_received_header(self):
        # Test email without the "Received" header (should show "Unknown IP")
        email_no_received = {
            'sender': 'suspicious@unknown.com',
            'recipient': 'user@example.com',
            'subject': 'Suspicious offer',
            'body': 'hxxp://suspicious-link.com',
            'timestamp': '2024-09-30T12:34:56'
        }
        self.processor.emails = [email_no_received]
        report = self.processor.generate_report()
        self.assertIn("IP: Unknown IP", report)

    def test_email_with_subject_only(self):
        # Test email with only a subject, no body
        email_subject_only = {
            'sender': 'unknown@unknown.com',
            'recipient': 'user@example.com',
            'subject': 'urgent action required',
            'body': '',
            'headers': {'Received': 'from 123.456.789.012'},
            'timestamp': '2024-09-30T12:34:56'
        }
        self.processor.emails = [email_subject_only]
        report = self.processor.generate_report()
        self.assertIn("Malicious Emails Detected", report)

    def test_generate_report(self):
        # Add regular emails to the processor and generate the report
        test_email_malicious = {
            'sender': 'malicious@untrustworthy.com',
            'recipient': 'user@example.com',
            'subject': 'urgent action required',
            'body': 'This is an important message. click here to verify your account.',
            'headers': {'Received': 'from 123.456.789.012'},
            'timestamp': '2024-09-30T12:34:56'
        }
        test_email_suspicious = {
            'sender': 'suspicious@unknown.com',
            'recipient': 'user@example.com',
            'subject': 'Special offer just for you',
            'body': 'Please review this offer: hxxp://suspicious-link.com',
            'headers': {'Received': 'from 111.222.333.444'},
            'timestamp': '2024-09-30T12:34:56'
        }
        test_email_trusted = {
            'sender': 'trusted@safe.com',
            'recipient': 'user@example.com',
            'subject': 'Your account has been updated',
            'body': 'No suspicious activity.',
            'headers': {'Received': 'from 123.456.789.012'},
            'timestamp': '2024-09-30T12:34:56'
        }
        self.processor.emails = [test_email_malicious, test_email_suspicious, test_email_trusted]
        report = self.processor.generate_report()
        self.assertIn("Malicious Emails Detected: 1", report)
        self.assertIn("Suspicious Emails Detected: 1", report)


class TestUtils(unittest.TestCase):

    def test_extract_ip_from_received(self):
        # Test extracting IP from the "Received" header
        received_header = "from 123.456.789.012 by example.com"
        ip = extract_ip_from_received(received_header)
        self.assertEqual(ip, '123.456.789.012')

        # Test with no IP
        received_header_no_ip = "from unknown by example.com"
        ip = extract_ip_from_received(received_header_no_ip)
        self.assertEqual(ip, 'Unknown IP')

    def test_extract_urls(self):
        # Test extracting URLs from a text body
        body_with_urls = "Check this out: hxxp://example.com and hxxp://test.com"
        urls = extract_urls(body_with_urls)
        self.assertEqual(len(urls), 2)
        self.assertIn('hxxp://example.com', urls)


if __name__ == '__main__':
    unittest.main()

import json
import os
import yaml
import smtplib
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv
from .PhishingEmail import PhishingEmail
from .utils import extract_ip_from_received, extract_urls

# Dictionary mapping keywords to suspicious activities
suspicious_activity_mapping = {
    "urgent": "False sense of Urgency",
    "verify your account": "False Authority",
    "click here": "Pretexting",
    "action required": "False sense of Urgency",
    "account locked": "Intimidation"
}

# Load environment variables from the .env file
load_dotenv('../config/send_email_credentials.env')

class EmailProcessor:
    """
    This class processes emails and generates phishing email reports. It identifies malicious and suspicious emails,
    extracts important metadata, and formats a comprehensive report.
    """
    def __init__(self):
        """Initialize the EmailProcessor with email data, keywords, and safe domains."""
        self.emails = []
        self.keywords = []
        self.safe_domains = []

    def load_emails(self, json_file):
        """
        Load emails from a JSON file.

        Args:
            json_file (str): Path to the input JSON file containing email data.
        """
        with open(json_file, 'r') as f:
            self.emails = json.load(f)

    def load_keywords_and_domains(self):
        """
        Load keywords and safe domains from a YAML configuration file.

        The YAML file contains keywords to detect malicious emails and a list of safe domains that are trusted.
        """
        base_path = os.path.dirname(os.path.abspath(__file__))
        config_file = os.path.join(base_path, '..', 'config', 'Indicators.yaml')

        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)

        self.keywords = config.get('keywords', [])
        self.safe_domains = config.get('safe_domains', [])

    def is_suspicious(self, email):
        """
        Check if the sender's domain is suspicious by comparing it to the list of trusted domains.

        Args:
            email (dict): The email data to check.

        Returns:
            bool: True if the domain is not trusted, False if trusted.
        """
        # Extract the domain from the sender's email address and compare it against the trusted domains list
        return self._extract_domain(email.get('sender', '')) not in self.safe_domains

    def is_malicious(self, email):
        """
        Check if the email contains malicious content based on the presence of specific keywords.

        Args:
            email (dict): The email data to check.

        Returns:
            bool: True if malicious keywords are found in the subject or body, False otherwise.
        """
        # Search for any keyword in either the body or the subject of the email
        return any(keyword in email.get('body', '').lower() or keyword in email.get('subject', '').lower()
                   for keyword in self.keywords)

    def email_status(self, email):
        """
        Determine the status of an email as trusted, suspicious, or malicious.

        Args:
            email (dict): The email data to check.

        Returns:
            tuple: A tuple containing the email's status (trusted, suspicious, or malicious), IP addresses,
                   domains, embedded URLs, and sender's IP address.
        """
        body = email.get('body', '').lower()  # Extract and lowercase the email body
        subject = email.get('subject', '').lower()  # Extract and lowercase the email subject
        received_header = email.get('headers', {}).get('Received', '')  # Get the 'Received' header to extract IP
        sender_ip = extract_ip_from_received(received_header)  # Extract the IP address from the header
        domain = self._extract_domain(email.get('sender', ''))  # Extract the domain from the sender's email address

        # If the email is from a trusted domain, mark it as "trusted"
        if not self.is_suspicious(email):
            return "trusted", [], [domain], [], sender_ip

        # Initialize lists to hold IP addresses and embedded URLs
        ip_addresses = [sender_ip]
        urls = extract_urls(body)  # Extract URLs from the email body

        # If the email contains malicious keywords, return its status as "malicious"
        if self.is_malicious(email):
            return "malicious", ip_addresses, [domain], urls, sender_ip

        # If the email has embedded URLs but no malicious content, mark it as "suspicious"
        if urls:
            return "suspicious", ip_addresses, [domain], urls, sender_ip

        # Otherwise, return it as "benign" (suspicious but no URLs or malicious content)
        return "benign", ip_addresses, [domain], urls, sender_ip

    def _extract_domain(self, sender):
        """
        Extract the domain from an email address.

        Args:
            sender (str): The sender's email address.

        Returns:
            str: The extracted domain.
        """
        return sender.split('@')[-1] if '@' in sender else ''  # Return the domain part of the email address

    def generate_report(self):
        """
        Generate a comprehensive phishing email report.

        The report includes details of malicious and suspicious emails, IP addresses, domains, affected accounts,
        suspicious keywords, and activities.

        Returns:
            str: The formatted report.
        """
        total_emails_scanned = len(self.emails)  # Count the total number of emails processed
        malicious_emails, suspicious_emails = [], []  # Initialize lists to hold malicious and suspicious emails
        malicious_ips_and_domains, suspicious_ips_and_domains = [], []  # Initialize lists for IPs and domains
        affected_accounts = set()  # Initialize a set to hold affected accounts (unique)
        suspicious_keywords_overall, suspicious_activities_overall = set(), set()  # Initialize sets for keywords/activities

        # Iterate through all emails to process each one
        for email in self.emails:
            email_status, ip_addresses, domains, urls, sender_ip = self.email_status(email)
            self._process_email(email, email_status, ip_addresses, domains, urls, sender_ip,
                                malicious_emails, suspicious_emails, malicious_ips_and_domains,
                                suspicious_ips_and_domains, affected_accounts, suspicious_keywords_overall,
                                suspicious_activities_overall)

        # Build and return the final report
        return self._build_report(total_emails_scanned, malicious_emails, suspicious_emails,
                                  malicious_ips_and_domains, suspicious_ips_and_domains, affected_accounts,
                                  suspicious_keywords_overall, suspicious_activities_overall)

    def _process_email(self, email, status, ip_addresses, domains, urls, sender_ip,
                       malicious_emails, suspicious_emails, malicious_ips_and_domains,
                       suspicious_ips_and_domains, affected_accounts, suspicious_keywords_overall,
                       suspicious_activities_overall):
        """
        Helper function to process each email based on its status (malicious or suspicious).

        Args:
            email (dict): The email to process.
            status (str): The email status (malicious, suspicious, trusted).
            ip_addresses (list): The list of IP addresses associated with the email.
            domains (list): The list of domains extracted from the email.
            urls (list): The list of embedded URLs in the email.
            sender_ip (str): The sender's IP address.
            malicious_emails (list): The list to store malicious emails.
            suspicious_emails (list): The list to store suspicious emails.
            malicious_ips_and_domains (list): The list to store IPs and domains for malicious emails.
            suspicious_ips_and_domains (list): The list to store IPs and domains for suspicious emails.
            affected_accounts (set): The set of affected email accounts.
            suspicious_keywords_overall (set): Set to track overall suspicious keywords.
            suspicious_activities_overall (set): Set to track overall suspicious activities.
        """
        # Handle malicious emails
        if status == "malicious":
            self._handle_malicious_email(email, ip_addresses, domains, urls, sender_ip,
                                         malicious_emails, malicious_ips_and_domains, affected_accounts,
                                         suspicious_keywords_overall, suspicious_activities_overall)
        # Handle suspicious emails
        elif status == "suspicious":
            self._handle_suspicious_email(email, ip_addresses, domains, urls, sender_ip,
                                          suspicious_emails, suspicious_ips_and_domains, affected_accounts,
                                          suspicious_activities_overall)

    def _handle_malicious_email(self, email, ip_addresses, domains, urls, sender_ip,
                                malicious_emails, malicious_ips_and_domains, affected_accounts,
                                suspicious_keywords_overall, suspicious_activities_overall):
        """
        Helper to handle malicious emails, extracting keywords and suspicious activities.

        Args:
            Same as _process_email.
        """
        suspicious_keywords = set()  # Track suspicious keywords found in this email
        suspicious_activities = self._get_suspicious_activities(email, urls, suspicious_keywords)  # Get suspicious activities

        # Update the overall sets with new keywords and activities
        suspicious_keywords_overall.update(suspicious_keywords)
        suspicious_activities_overall.update(suspicious_activities)

        # Create a PhishingEmail object for the current email
        phishing_email = PhishingEmail(
            timestamp=email['timestamp'],
            sender=email['sender'],
            recipient=email['recipient'],
            subject=email['subject'],
            suspicious_keywords=suspicious_keywords,
            urls=urls,
            sender_ip=sender_ip,
            suspicious_activities=suspicious_activities
        )
        malicious_emails.append(phishing_email)  # Add to the list of malicious emails

        # Store the associated IP addresses and domains
        for ip, domain in zip(ip_addresses, domains):
            malicious_ips_and_domains.append((ip, domain))
        affected_accounts.add(email['recipient'])  # Track affected accounts

    def _handle_suspicious_email(self, email, ip_addresses, domains, urls, sender_ip,
                                 suspicious_emails, suspicious_ips_and_domains, affected_accounts,
                                 suspicious_activities_overall):
        """
        Helper to handle suspicious emails, recording suspicious activities.

        Args:
            Same as _process_email.
        """
        suspicious_activities = {"Untrusted sender"}  # Initialize with "Untrusted sender"
        if urls:
            suspicious_activities.add("Embedded URL")  # If URLs are present, mark it as embedded URLs
        suspicious_activities_overall.update(suspicious_activities)  # Update the overall activities set

        # Create a PhishingEmail object for the current suspicious email
        phishing_email = PhishingEmail(
            timestamp=email['timestamp'],
            sender=email['sender'],
            recipient=email['recipient'],
            subject=email['subject'],
            suspicious_keywords=[],  # No suspicious keywords for suspicious emails
            urls=urls,
            sender_ip=sender_ip,
            suspicious_activities=suspicious_activities
        )
        suspicious_emails.append(phishing_email)  # Add to the list of suspicious emails

        # Store the associated IP addresses and domains
        for ip, domain in zip(ip_addresses, domains):
            suspicious_ips_and_domains.append((ip, domain))
        affected_accounts.add(email['recipient'])  # Track affected accounts

    def _get_suspicious_activities(self, email, urls, suspicious_keywords):
        """
        Extract suspicious activities from the email based on keywords and URLs.

        Args:
            email (dict): The email data.
            urls (list): The list of embedded URLs in the email.
            suspicious_keywords (set): Set to collect suspicious keywords.

        Returns:
            set: The set of suspicious activities.
        """
        suspicious_activities = {"Untrusted sender"}  # Start with "Untrusted sender"
        if urls:
            suspicious_activities.add("Embedded URL")  # Add "Embedded URL" if URLs are found
        # Loop through keywords and check if they exist in the body or subject
        for keyword in self.keywords:
            if keyword in email.get('body', '').lower() or keyword in email.get('subject', '').lower():
                suspicious_keywords.add(keyword)  # Add the keyword to the set
                suspicious_activities.add(suspicious_activity_mapping.get(keyword, "Unknown Activity"))
        return suspicious_activities

    def _build_report(self, total_emails_scanned, malicious_emails, suspicious_emails,
                      malicious_ips_and_domains, suspicious_ips_and_domains, affected_accounts,
                      suspicious_keywords_overall, suspicious_activities_overall):
        """
        Build the phishing email report with details, including percentages of malicious/suspicious emails.

        Args:
            total_emails_scanned (int): The total number of emails processed.
            malicious_emails (list): List of malicious emails.
            suspicious_emails (list): List of suspicious emails.
            malicious_ips_and_domains (list): List of IPs and domains for malicious emails.
            suspicious_ips_and_domains (list): List of IPs and domains for suspicious emails.
            affected_accounts (set): Set of affected accounts.
            suspicious_keywords_overall (set): Set of suspicious keywords across all emails.
            suspicious_activities_overall (set): Set of suspicious activities across all emails.

        Returns:
            str: The formatted report.
        """
        # Calculate the percentage of malicious and suspicious emails
        malicious_percentage = (len(malicious_emails) / total_emails_scanned) * 100 if total_emails_scanned > 0 else 0
        suspicious_percentage = (len(suspicious_emails) / total_emails_scanned) * 100 if total_emails_scanned > 0 else 0

        # Initialize the report with basic info and percentages
        report_lines = [
            "===========================================",
            "         Phishing Email Report             ",
            "===========================================",
            f"Total Emails Scanned: {total_emails_scanned}\n",
            f"Malicious Emails Detected: {len(malicious_emails)} ({malicious_percentage:.2f}%)\n",
            f"Suspicious Emails Detected: {len(suspicious_emails)} ({suspicious_percentage:.2f}%)\n",
            "This report provides an overview of malicious and suspicious emails.\n"
        ]

        if malicious_emails or suspicious_emails:
            report_lines.append("Summary of Findings:")
            if suspicious_keywords_overall:
                report_lines.append("\nSuspicious Keywords Found:")
                report_lines.extend([f"  - {kw}" for kw in suspicious_keywords_overall])

            if suspicious_activities_overall:
                report_lines.append("\nSuspicious Activities Found:")
                report_lines.extend([f"  - {activity}" for activity in suspicious_activities_overall])

            # Append details of malicious and suspicious emails to the report
            self._append_email_details(malicious_emails, "Malicious Emails", report_lines)
            self._append_email_details(suspicious_emails, "Suspicious Emails", report_lines)

            # Add information about affected accounts and IPs/domains
            report_lines.append(f"\nTotal Affected Accounts: {len(affected_accounts)}")
            report_lines.append(f"Affected Accounts: {', '.join(affected_accounts)}")

            # Append IP addresses and domains for malicious and suspicious emails
            self._append_ip_and_domains(malicious_ips_and_domains, "Malicious", report_lines)
            self._append_ip_and_domains(suspicious_ips_and_domains, "Suspicious", report_lines)

        else:
            report_lines.append("No suspicious or malicious emails were detected.")

        report_lines.append("\nEnd of Report")
        return '\n'.join(report_lines)

    def _append_email_details(self, emails, title, report_lines):
        """
        Append details for malicious or suspicious emails to the report.

        Args:
            emails (list): List of phishing emails.
            title (str): Title for the section (e.g., Malicious Emails).
            report_lines (list): List of report lines to append to.
        """
        if emails:
            report_lines.append(f"\n{title} Detected: {len(emails)}")
            report_lines.append(f"Details of {title}:\n")
            for email in emails:
                report_lines.append(str(email))
                report_lines.append("-" * 50)

    def _append_ip_and_domains(self, ips_and_domains, category, report_lines):
        """
        Append IP addresses and domains to the report.

        Args:
            ips_and_domains (list): List of IP addresses and domains.
            category (str): The category (e.g., Malicious or Suspicious).
            report_lines (list): List of report lines to append to.
        """
        if ips_and_domains:
            report_lines.append(f"\n{category} IP Addresses and Domains:")
            for ip, domain in set(ips_and_domains):
                report_lines.append(f"  IP: {ip}, Domain: {domain}")

    def send_email(self, report, recipient_email):
        """
        Send the phishing report via email.

        Args:
            report (str): The generated report content.
            recipient_email (str): The email address to send the report to.
        """
        sender_email = os.getenv('EMAIL_ADDRESS')
        sender_password = os.getenv('APP_PASSWORD')

        # Create the email message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = "Phishing Email Report"

        msg.attach(MIMEText(report, 'plain'))

        # Send the email via SMTP server
        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()  # Start TLS encryption
                server.login(sender_email, sender_password)  # Login to the email server
                server.send_message(msg)  # Send the email
            print(f"Email sent to {recipient_email}.")
        except Exception as e:
            print(f"Failed to send email: {e}")

import json
import os
import yaml
import smtplib
#import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
#from datetime import datetime
from dotenv import load_dotenv
from .PhishingEmail import PhishingEmail
from .utils import extract_ip_from_received, extract_urls, extract_domain, extract_domain_from_received

#Variable Constants
MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"

# Dictionary mapping keywords to suspicious activities
suspicious_activity_mapping = {
    "urgent": "Urgency",
    "verify your account": "False Authority",
    "click here": "Pretexting",
    "action required": "Urgency",
    "account locked": "Intimidation"
}

# Load environment variables from the .env file
#load_dotenv('../config/send_email_credentials.env') Only works when running the code locally and not in docker container
#load_dotenv('/app/.env') #need to reference docker container file

# Check if the program is running in Docker
if os.path.exists('/.dockerenv'):
    # Running in Docker, load the Docker .env file
    load_dotenv('/app/.env')
    #print("Running inside Docker")
else:
    # Running locally, load the local .env file
    load_dotenv('../config/send_email_credentials.env')
    #print("Running locally")


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

        The YAML file contains:
        - 'keywords': A list of keywords used to detect potential malicious emails.
        - 'safe_domains': A list of domains considered trusted (emails from these domains are not flagged as suspicious or malicious).

        This function reads the configuration from the 'Indicators.yaml' file and updates the
        'keywords' and 'safe_domains' attributes of the class.

        Raises:
            FileNotFoundError: If the configuration file is not found.
        """
        # Get the directory of the current file (email_processor.py) to form the base path
        base_path = os.path.dirname(os.path.abspath(__file__))

        # Construct the full path to the 'Indicators.yaml' file, which is assumed to be located in the 'config' directory one level up
        config_file = os.path.join(base_path, '..', 'config', 'Indicators.yaml')

        # Open the YAML configuration file in read mode
        with open(config_file, 'r') as f:
            # Load the contents of the YAML file into a Python dictionary
            config = yaml.safe_load(f)

        # Extract the list of 'keywords' from the YAML file; if the key doesn't exist, use an empty list by default
        self.keywords = config.get('keywords', [])

        # Extract the list of 'safe_domains' from the YAML file; if the key doesn't exist, use an empty list by default
        self.safe_domains = config.get('trusted_domains', [])

    def validate_email(self, email):
        """
        Validate email fields, raise an error if any field is missing or empty.

        Args:
            email (dict): The email data.

        Raises:
            KeyError: If a required field is missing or empty.
        """
        required_fields = ['sender', 'recipient', 'subject', 'body', 'headers', 'timestamp']
        for field in required_fields:
            if field not in email or not email[field]:
                raise KeyError(field)

    def is_suspicious(self, email):
        """
        Check if the sender's domain is suspicious by comparing it to the list of trusted domains.

        Args:
            email (dict): The email data to check.

        Returns:
            bool: True if the domain is not trusted, False if trusted.
        """
        # Extract the domain from the sender's email address and compare it against the trusted domains list
        return extract_domain(email.get('sender', '')) not in self.safe_domains

    def is_malicious(self, email):
        """
        Check if the email contains malicious content based on the presence of specific keywords or if the sender and received fields do not match.

        Args:
            email (dict): The email data to check.

        Returns:
            bool: True if malicious keywords are found in the subject or body, or if the sender does not match received from, False otherwise.
        """
        # If the sender field and the received header do not match, flag the email as malicious
        if not self.compare_sender_and_received_domains(email):
            return True
        # Search for any keyword in either the body or the subject of the email
        return any(keyword in email.get('body', '').lower() or keyword in email.get('subject', '').lower()
                   for keyword in self.keywords)

    def get_email_status(self, email):
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
        domain = extract_domain(email.get('sender', ''))  # Extract the domain from the sender's email address

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


    def compare_sender_and_received_domains(self, email):
        """
        Compare the sender's domain with the domain in the 'Received' header.

        Args:
            email (dict): The email data containing the sender and headers.

        Returns:
            bool: True if the domains match, False otherwise.
        """
        # Extract the sender's domain
        sender_domain = extract_domain(email.get('sender', ''))
        # Extract the domain from the 'Received' header
        received_header = email.get('headers', {}).get('Received', '')
        received_domain = extract_domain_from_received(received_header)

        # Compare both domains and return the result
        return sender_domain == received_domain

    def generate_report(self):
        """
        Generate a comprehensive phishing email report, including any parsing errors.

        The report includes details of malicious and suspicious emails, IP addresses, domains, affected accounts,
        suspicious keywords, and activities. Errors encountered during processing are appended at the end of the report.

        Returns:
            str: The formatted report.
        """
        total_emails_scanned = len(self.emails)  # Count the total number of emails processed
        malicious_emails, suspicious_emails = [], []  # Initialize lists to hold malicious and suspicious emails
        malicious_ips_and_domains, suspicious_ips_and_domains = [], []  # Initialize lists for IPs and domains
        affected_accounts = set()  # Initialize a set to hold affected accounts (unique)
        suspicious_keywords_overall, suspicious_activities_overall = set(), set()  # Initialize sets for keywords/activities
        parsing_errors = []  # List to store parsing errors

        # Iterate through all emails to process each one
        for idx, email in enumerate(self.emails, start=1):
            try:
                self.validate_email(email) #Check to see if the email is in the correct format without any missing entries
                # Get the status (trusted,malicious,suspicious, or benign)
                email_status, ip_addresses, domains, urls, sender_ip = self.get_email_status(email) #Store the returned email data to create a PhishingEmail object
                self.process_email(email, email_status, ip_addresses, domains, urls, sender_ip,
                                    malicious_emails, suspicious_emails, malicious_ips_and_domains,
                                    suspicious_ips_and_domains, affected_accounts, suspicious_keywords_overall,
                                    suspicious_activities_overall)
            except KeyError as e:
                parsing_errors.append(f"Email {idx}: Error Parsing field '{e}'. Please check the input data")
            except Exception as e:
                parsing_errors.append(f"Email {idx}: Error - {str(e)}.")

        report = self.build_report(total_emails_scanned, malicious_emails, suspicious_emails,
                                    malicious_ips_and_domains, suspicious_ips_and_domains, affected_accounts,
                                    suspicious_keywords_overall, suspicious_activities_overall,parsing_errors)

        return report

    def process_email(self, email, status, ip_addresses, domains, urls, sender_ip,
                       malicious_emails, suspicious_emails, malicious_ips_and_domains,
                       suspicious_ips_and_domains, affected_accounts, suspicious_keywords_overall,
                       suspicious_activities_overall):
        """
        Function to process each email based on its status (malicious or suspicious).
        ***Currently, could be removed and 'handle_email' could be modified to be used in place of this, however this simplifies future
        email classification additions that may require different logic to handle.

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
        if status == MALICIOUS:
            self.handle_email(
                email, status, ip_addresses, domains, urls, sender_ip,
                malicious_emails, malicious_ips_and_domains, affected_accounts,
                suspicious_keywords_overall, suspicious_activities_overall
            )
        # Handle suspicious emails
        elif status == SUSPICIOUS:
            self.handle_email(
                email, status, ip_addresses, domains, urls, sender_ip,
                suspicious_emails, suspicious_ips_and_domains, affected_accounts,
                suspicious_keywords_overall, suspicious_activities_overall
            )

    def handle_email(self, email, status, ip_addresses, domains, urls, sender_ip,
                      emails_list, ips_and_domains_list, affected_accounts,
                      suspicious_keywords_overall, suspicious_activities_overall):
        """
        Helper function to handle both malicious and suspicious emails, extracting keywords and suspicious activities.

        Args:
            email (dict): The email to process.
            status (str): The email status (malicious, suspicious, trusted).
            ip_addresses (list): The list of IP addresses associated with the email.
            domains (list): The list of domains extracted from the email.
            urls (list): The list of embedded URLs in the email.
            sender_ip (str): The sender's IP address.
            emails_list (list): The list to store either malicious or suspicious emails.
            ips_and_domains_list (list): The list to store IPs and domains for either malicious or suspicious emails.
            affected_accounts (set): The set of affected email accounts.
            suspicious_keywords_overall (set): Set to track overall suspicious keywords.
            suspicious_activities_overall (set): Set to track overall suspicious activities.
        """
        suspicious_keywords = set()  # Track suspicious keywords found in this email
        suspicious_activities = self.get_suspicious_activities(email, urls, suspicious_keywords)  # Get suspicious activities

        # If it's a malicious email, track suspicious keywords in a set
        if status == MALICIOUS:
            suspicious_keywords_overall.update(suspicious_keywords)

        # Always update suspicious activities, malicious or suspicious
        suspicious_activities_overall.update(suspicious_activities)

        # Create a PhishingEmail object for the current email (malicious or suspicious)
        phishing_email = PhishingEmail(
            timestamp=email['timestamp'],
            sender=email['sender'],
            recipient=email['recipient'],
            subject=email['subject'],
            suspicious_keywords=suspicious_keywords if status == MALICIOUS else [],
            # Only store keywords for malicious
            urls=urls,
            sender_ip=sender_ip,
            suspicious_activities=suspicious_activities
        )
        emails_list.append(phishing_email)  # Add to the list of either malicious or suspicious emails

        # Store the associated IP addresses and domains
        for ip, domain in zip(ip_addresses, domains):
            ips_and_domains_list.append((ip, domain))
        affected_accounts.add(email['recipient'])  # Track affected accounts

    def get_suspicious_activities(self, email, urls, suspicious_keywords):
        """
        Extract suspicious activities from the email based on keywords and URLs.

        Args:
            email (dict): The email data.
            urls (list): The list of embedded URLs in the email.
            suspicious_keywords (set): Set to collect suspicious keywords.

        Returns:
            set: The set of suspicious activities.
        """
        suspicious_activities = {"Untrusted sender"}  # Any email flagged will be from an untrusted sender.
        if urls:
            suspicious_activities.add("Embedded URL")  # Add "Embedded URL" if URLs are found
        if not self.compare_sender_and_received_domains(email):
            suspicious_activities.add("Typosquatting")  # Add "Typosquatting" if the sender address is spoofed
        # Loop through keywords and check if they exist in the body or subject
        for keyword in self.keywords:
            if keyword in email.get('body', '').lower() or keyword in email.get('subject', '').lower():
                suspicious_keywords.add(keyword)  # Add the keyword to the set
                suspicious_activities.add(suspicious_activity_mapping.get(keyword, "Unknown Activity"))
        return suspicious_activities

    def build_report(self, total_emails_scanned, malicious_emails, suspicious_emails,
                      malicious_ips_and_domains, suspicious_ips_and_domains, affected_accounts,
                      suspicious_keywords_overall, suspicious_activities_overall,parsing_errors):
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
            parsing_errors (list): List of parsing errors that occurred during the email scanning process.

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
            "This report provides an overview of malicious and suspicious emails.\n"
            "Emails flagged as malicious are from untrusted senders and contain phishing email keywords or have a mismatch between sender and received feilds.\n"
            "Suspicious emails do not contain known keywords but do contain embedded URLs and should be investigated further.\n"
            f"Total Emails Scanned: {total_emails_scanned}\n",
            f"Malicious Emails Detected: {len(malicious_emails)} ({malicious_percentage:.2f}%)\n",
            f"Suspicious Emails Detected: {len(suspicious_emails)} ({suspicious_percentage:.2f}%)\n",

        ]
        if parsing_errors:
            report_lines.append( "***Errors encountered during processing***:\n")
            report_lines.append("\n".join(f" - {error}" for error in parsing_errors))
        if malicious_emails or suspicious_emails:
            report_lines.append("\nSummary of Findings:")
            # Add information about affected accounts and IPs/domains
            report_lines.append(f"\nTotal Affected Accounts: {len(affected_accounts)}")
            report_lines.append(f"Affected Accounts: {', '.join(affected_accounts)}")
            if suspicious_keywords_overall:
                report_lines.append("\nSuspicious Keywords Found:")
                report_lines.extend([f"  - {kw}" for kw in suspicious_keywords_overall])

            if suspicious_activities_overall:
                report_lines.append("\nSuspicious Activities Found:")
                report_lines.extend([f"  - {activity}" for activity in suspicious_activities_overall])

            # Append details of malicious and suspicious emails to the report
            self.append_email_details(malicious_emails, "Malicious Emails", report_lines)
            self.append_email_details(suspicious_emails, "Suspicious Emails", report_lines)

            report_lines.append("\nConsiderations for security configurations:")

            # Append IP addresses and domains for malicious and suspicious emails
            self.append_ip_and_domains(malicious_ips_and_domains, "Malicious", report_lines)
            self.append_ip_and_domains(suspicious_ips_and_domains, "Suspicious", report_lines)

        else:
            report_lines.append("No suspicious or malicious emails were detected.")

        report_lines.append("\nEnd of Report")
        return '\n'.join(report_lines)

    def append_email_details(self, emails, title, report_lines):
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

    def append_ip_and_domains(self, ips_and_domains, category, report_lines):
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

# Phishing Email Detection System

This project is a Python-based phishing email detection system. It analyzes emails, classifies them as trusted, suspicious, or malicious, and generates a detailed report. It also supports sending the generated report via email.

## Features

- Detects suspicious and malicious emails based on sender, keywords, and URLs.
- Classifies emails into categories:
  - **Trusted**: Emails from trusted domains.
  - **Benign**: Emails not from trusted domains but no reason to suspect malicious activity (no embedded URLs or malicious keywords).
  - **Suspicious**: Emails from untrusted domains containing embedded URLs but no malicious keywords.
  - **Malicious**: Emails containing malicious keywords from untrusted domains.
- Generates a detailed report containing suspicious and malicious emails with reasoning.
- Supports sending the report to a specified email address.
- Can be extended and unit tested.

## Project Structure

**email_processor.py** # Core logic for processing emails

**main.py** # Main entry point for running the program 

**utils.py** # Utility functions for extracting IPs, URLs, etc. 

**PhishingEmail.py** # PhishingEmail class representing each email's suspicious attributes 

**Indicators.yaml** # YAML configuration file containing keywords and trusted domains

**send_email_credentials.env** # Environment variables for email credentials 

**test_email_processor.py** # Unit tests for the program

## Requirements

- Python 3.10+
- Required Python libraries:
  - `yaml`
  - `dotenv`
  - `smtplib`
  - `re`
  - `unittest`

You can install the required packages using the following command:

```bash
pip install pyyaml python-dotenv
Setup
Clone the Repository:

bash
Copy code
git clone <repository-url>
cd <repository-folder>
Set Up Environment Variables:

Create a .env file in the root directory for email credentials (or rename send_email_credentials.env). Populate it as follows:

makefile
Copy code
EMAIL_ADDRESS=<your-email-address>
APP_PASSWORD=<your-email-password>
These credentials will be used to send the generated report to a specified recipient.

Create Configuration File:

Create the Indicators.yaml file for phishing detection keywords and trusted domains. Example:

yaml
Copy code
keywords:
  - urgent
  - verify your account
  - click here
  - action required
  - account locked
safe_domains:
  - safe.com
  - trusted.com
  - service.com
Running the Program
Command-Line Usage
To run the program and generate a report:

bash
Copy code
python email_scan.py <input_json_file> <output_report_file> [<recipient_email>]
<input_json_file>: Path to the input JSON file containing email data.
<output_report_file>: Path to the output report file.
[<recipient_email>]: (Optional) Email address to send the generated report.
Example:

bash
Copy code
python email_scan.py emails.json report.txt recipient@example.com
Sample Input JSON Structure
Here's an example of what the input JSON file should look like:

json
Copy code
[
    {
        "sender": "phisher@malicious.com",
        "recipient": "user@example.com",
        "subject": "Urgent: Verify your account",
        "timestamp": "2024-08-27T08:30:00Z",
        "body": "Click here to verify your account: hxxp://malicious[.]com",
        "headers": {
            "Received": "from malicious.com (malicious.com [192.0.2.1])",
            "Content-Type": "text/html; charset=UTF-8"
        }
    }
]
Output
The program generates a detailed report with the following structure:

markdown
Copy code
===========================================
         Phishing Email Report             
===========================================
Total Emails Scanned: 3

Malicious Emails Detected: 2 (66.67%)
Suspicious Emails Detected: 1 (33.33%)

This report provides an overview of malicious and suspicious emails.

Summary of Findings:

Suspicious Keywords Found:
  - verify your account
  - click here
  - urgent

Suspicious Activities Found:
  - Embedded URL
  - False Authority
  - Pretexting
  - False sense of Urgency
  - Untrusted sender

Details of Malicious Emails:
...
Unit Testing
Unit tests are included in the test_email_processor.py file. You can run the tests using:

bash
Copy code
python -m unittest tests.test_email_processor
The tests cover various cases such as email classification (trusted, suspicious, malicious) and report generation.

Sample Unit Test Command:
bash
Copy code
python -m unittest test_email_processor.TestEmailProcessor
Customization
Add or Modify Keywords and Domains:

You can update Indicators.yaml to change the keywords that trigger a phishing alert and trusted domains.
Modify Report Formatting:

The generate_report function in email_processor.py can be adjusted to change how reports are formatted.
Extend with More Features:

You can easily add more phishing detection mechanisms by extending email_processor.py and adding more utility functions in utils.py.
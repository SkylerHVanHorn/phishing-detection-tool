# Phishing Email Detection Program

This project is a Python-based phishing email detection system. It analyzes emails, classifies them as either trusted, benign, suspicious, or malicious, and generates a detailed report. It also supports sending the generated report via email.

## Features

- Detects suspicious and malicious emails based on sender, keywords, and URLs.
- Classifies emails into categories:
  - **Trusted**: Emails from trusted domains.
  - **Benign**: Emails not from trusted domains but no reason to suspect malicious activity (no embedded URLs,malicious keywords, etc.).
  - **Suspicious**: Emails from untrusted domains containing embedded URLs but no malicious keywords.
  - **Malicious**: Emails containing malicious keywords from untrusted domains and/or evidence of typosquatting.
- Generates a detailed report containing suspicious and malicious emails with reasoning.
- Supports sending the report to a specified email address.
- Can be extended and unit tested.

## Project Structure

**email_processor.py** # Core logic for processing emails

**email_scan.py** # Main entry point for running the program 

**utils.py** # Utility functions for extracting IPs, URLs, etc. 

**PhishingEmail.py** # PhishingEmail class representing each email's suspicious attributes 

**Indicators.yaml** # YAML configuration file containing keywords and trusted domains

**send_email_credentials.env** # Environment variables for email credentials 

**test_email_processor.py** # Unit tests for the program

### Input JSON File
This program takes a JSON file of email meta data as an argument to parse and provide a report for.

Here's an example of what the input JSON file should look like:
```json
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
```

### Testing

Unit tests are included in the test_email_processor.py file. You can run the tests using:
```bash
python -m unittest tests.test_email_processor
```
The tests cover various cases such as email classification (trusted, suspicious, malicious) and report generation.

#### Add or Modify Keywords and Domains:

You can update Indicators.yaml to change the keywords that trigger a phishing alert and trusted domains.

## Running the Phishing Detection Tool with Docker
This project is packaged as a Docker container to make it easy to execute on any machine with Docker installed. Follow the steps below to pull the Docker image from Docker Hub and execute the tool.

Prerequisites

Docker: Ensure Docker is installed and running on your system. You can install Docker following the instructions from the official Docker documentation.

Docker Image
This project has been pushed to Docker Hub under the repository: skyhvh/phishing-detection-tool.

Steps to Run 

1. Pull the Docker Image

First, pull the Docker image from Docker Hub:
```bash
docker pull skyhvh/phishing-detection-tool:latest
```
2. Prepare the Input Files

Ensure you have your sample_emails.json file or a similarly structured JSON file that contains the email data. This file should be available on your local machine.

3. Run the Docker Container

You can run the container with the following command:
```bash
docker run -it \
  -v /path/to/your/sample_emails.json:/app/sample_emails.json \
  -v /path/to/your/output_directory:/app/reports \
  skyhvh/phishing-detection-tool:latest python email_scan.py /app/sample_emails.json /app/reports/output_report.txt
````
Replace /path/to/your/sample_emails.json with the absolute path to your sample_emails.json file.

Replace /path/to/your/output_directory with the absolute path to the directory where you want the report to be saved.
The program will generate output_report.txt in the specified output directory.

Once the Docker container finishes running, the report will be available in your specified output directory on your local machine. You can open and review the report, which will contain details about any phishing or suspicious emails found.

Example
If you have your sample_emails.json file located at /home/user/sample_emails.json and you want to save the report in /home/user/reports, you would run:
```bash
docker run -it \
  -v /home/user/sample_emails.json:/app/sample_emails.json \
  -v /home/user/reports:/app/reports \
  skyhvh/phishing-detection-tool:latest python email_scan.py /app/sample_emails.json /app/reports/output_report.txt
````

Note: Somtimes Docker can get confused when mounting single files. If the above does not work, you can try mounting the entire directory when sample_emails.json is located:

```bash
docker run -it \
    -v /home/user/Desktop/:/app/data \
    -v /home/user/Desktop/:/app/reports \
    skyhvh/phishing-detection-tool:latest python email_scan.py /app/data/sample_emails.json /app/reports/output_report.txt
````
## Running Phishing Detection Tool Locally after downloading from GitHub
## Requirements

- Python 3.10+
- Required Python libraries:
  - `yaml`
  - `dotenv`
  - `smtplib`

You can install the required packages using the following command:

```bash
pip install pyyaml python-dotenv smtplib
```
Clone the Repository:

git clone repository-url \
cd repository-folder 

### Set Up Environment Variables:

Create a .env file in the root directory for email credentials (or rename send_email_credentials.env). Populate it as follows:

EMAIL_ADDRESS= your-email-address \
APP_PASSWORD= your-email-password \
These credentials will be used to send the generated report to a specified recipient.

Create Configuration File:

Create the Indicators.yaml file for phishing detection keywords and trusted domains. Example:

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

Running the Program from the command line

To run the program and generate a report:
```bash
python email_scan.py <input_json_file> <output_report_file> [<recipient_email>]
<input_json_file>: Path to the input JSON file containing email data. \
<output_report_file>: Path to the output report file. \
[<recipient_email>]: (Optional) Email address to send the generated report.
```
Output Report Format
The output report generated by the phishing detection tool provides a detailed analysis of all scanned emails, classifying them as malicious, suspicious, or trusted. The report includes key information such as embedded URLs, suspicious keywords, and any parsing errors encountered during the process.

Report Sections:
Summary of Emails Scanned

Total Emails Scanned: The total number of emails analyzed.
Malicious Emails Detected: Count and percentage of emails classified as malicious.
Suspicious Emails Detected: Count and percentage of emails classified as suspicious.
Errors Encountered

Lists any parsing errors encountered while scanning the emails, such as missing or improperly formatted fields.
Details of Malicious and Suspicious Emails

Sender, Recipient, and Subject: Key metadata of each email.
IP Addresses and Domains: Extracted IPs and domains from the email headers and body.
Suspicious Keywords Found: Keywords that indicate potential phishing content.
Suspicious Activities: Describes the type of suspicious activity identified, such as:
Urgency
False Authority
Typosquatting
Pretexting
Embedded URLs
Considerations for Security Configurations

Lists all malicious and suspicious IP addresses and domains found during the scan.

Example Report:
```
=========================================== 
         Phishing Email Report             
===========================================
This report provides an overview of malicious and suspicious emails.

Total Emails Scanned: 10

Malicious Emails Detected: 2 (20.00%)
Suspicious Emails Detected: 1 (10.00%)

Errors encountered during processing:
 - Email 3: Missing field 'subject'.
 - Email 5: Error Parsing field 'headers'. Please check the input data.

Summary of Findings:
Total Affected Accounts: 3
Affected Accounts: user1@example.com, user2@example.com, user3@example.com

Suspicious Keywords Found:
  - verify your account
  - click here

Suspicious Activities Found:
  - Urgency
  - Embedded URL
  - Typosquatting

Malicious Emails Detected: 2
Details of Malicious Emails:
[2024-08-27T08:30:00] From: phisher@malicious.com (IP: 192.0.2.1) To: user@example.com Subject: Urgent: Verify your account
  Suspicious Activity: Urgency, Embedded URL, Typosquatting
  Embedded URLs:
    hxxp://malicious[.]com
...

Considerations for security configurations:
Malicious IP Addresses and Domains:
  IP: 192.0.2.1, Domain: malicious.com
```
### Next Improvements
1. Integrate user interaction to confirm if suspicious emails are in fact malicious
2. Log 'malicious' email sender domains as an 'untrusted domain' indicator and use that to process future emails faster
3. Connect to SQL database for logging reports regularly.
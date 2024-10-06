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
## Running Phishing Detection Tool Locally after downloading from GitHub
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
```
Clone the Repository:

git clone <repository-url> \
cd <repository-folder> 

### Set Up Environment Variables:

Create a .env file in the root directory for email credentials (or rename send_email_credentials.env). Populate it as follows:

EMAIL_ADDRESS=<your-email-address> \
APP_PASSWORD=<your-email-password> \
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

### Next Improvements
1. Integrate user interaction to confirm if suspicious emails are in fact malicious
2. Log 'malicious' email sender domains as an 'untrusted domain' indicator and use that to process future emails faster
3. Connect to SQL database for logging reports regularly.
import sys
from email_processor.email_processor import EmailProcessor

def main(json_file, output_file, recipient_email=None):
    """Main function to process emails and generate a report.

    Args:
        json_file (str): Path to the input JSON file containing email data.
        output_file (str): Path to the output report file.
        recipient_email (str, optional): Email address to send the report to. Defaults to None.
    """
    # Create an instance of the EmailProcessor class
    processor = EmailProcessor()

    # Load emails from the specified JSON file
    processor.load_emails(json_file)

    # Load keywords and safe domains from the configuration file
    processor.load_keywords_and_domains()

    # Generate the report based on the loaded emails
    report = processor.generate_report()

    # Write the report to the specified output file
    with open(output_file, 'w') as f:
        f.write(report)

    print(f"Report generated: {output_file}")

    # If a recipient email is provided, send the report via email
    if recipient_email:
        processor.send_email(report, recipient_email)

if __name__ == "__main__":
    # Check if the correct number of command-line arguments are provided
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python email_scan.py <input_json_file> <output_report_file> [<recipient_email>]")
        sys.exit(1)

    # Assign command-line arguments to variables
    input_json_file = sys.argv[1]
    output_report_file = sys.argv[2]
    recipient_email = sys.argv[3] if len(sys.argv) == 4 else None

    # Execute the main function
    main(input_json_file, output_report_file, recipient_email)
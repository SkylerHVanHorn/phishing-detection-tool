import re

def extract_ip_from_received(received_header):
    """Extract the IP address from the received header using regex.

    Args:
        received_header (str): The received header string from an email.

    Returns:
        str: The extracted IP address or 'Unknown IP' if no valid IP is found.
    """
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # Define regex pattern for matching IP addresses
    matches = re.findall(ip_pattern, received_header)  # Find all matches of the pattern
    return matches[-1] if matches else 'Unknown IP'  # Return the last match if multiple, else 'Unknown IP'

def extract_urls(text):
    """Extract URLs from a given text using regex.

    Args:
        text (str): The text to search for URLs.

    Returns:
        list: A list of extracted URLs.
    """
    url_pattern = r'hxxp?://[^\s]+'
    return re.findall(url_pattern, text)  # Find all URLs in the text
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
    url_pattern = r'hxxps?://[^\s]+'
    return re.findall(url_pattern, text)  # Find all URLs in the text

def extract_domain_from_received(received_header):
    """
    Extract the domain from the 'Received' header using regex.

    Args:
        received_header (str): The 'Received' header from an email.

    Returns:
        str: The extracted domain or an empty string if not found.
    """
    # Regex pattern to extract the domain from the Received header
    match = re.search(r'from\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', received_header)
    if match:
        return match.group(1)
    return ''

def extract_domain(sender):
    """
    Extract the domain from the sender's email address.

    Args:
        sender (str): The sender's email address.

    Returns:
        str: The extracted domain.
    """
    return sender.split('@')[-1] if '@' in sender else ''

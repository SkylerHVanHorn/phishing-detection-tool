class PhishingEmail:
    def __init__(self, timestamp, sender, recipient, subject, suspicious_keywords, urls, sender_ip, suspicious_activities):
        self.timestamp = timestamp
        self.sender = sender
        self.recipient = recipient
        self.subject = subject
        self.suspicious_keywords = suspicious_keywords
        self.urls = urls
        self.sender_ip = sender_ip
        self.suspicious_activities = suspicious_activities  # New field for suspicious activities

    def __str__(self):
        keywords_str = ', '.join(self.suspicious_keywords) if self.suspicious_keywords else 'None'
        urls_str = '\n    '.join(self.urls) if self.urls else 'None'
        activities_str = ', '.join(self.suspicious_activities) if self.suspicious_activities else 'None'

        return (f"[{self.timestamp}] From: {self.sender} (IP: {self.sender_ip}) To: {self.recipient} Subject: {self.subject}\n"
                f"  Suspicious Activity: {activities_str}\n"
                f"  Suspicious Keywords Found: {keywords_str}\n"
                f"  Embedded URLs:\n    {urls_str}")

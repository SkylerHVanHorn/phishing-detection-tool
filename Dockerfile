# Use an official Python runtime as a base image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Copy the .env file from the config directory
COPY config/send_email_credentials.env /app/.env

# Install any Python packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port if your application serves web content (optional)
# EXPOSE 8000

# Define environment variables (optional)
# ENV NAME value

# Set the entry point to run the application
CMD ["python", "email_scan.py"]

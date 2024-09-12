# Use the official Python 3.11 image with Alpine
FROM python:3.11-alpine

# Set the working directory
WORKDIR /app

# Copy the application code
COPY . /app

# Install the required Python packages
RUN pip install -r requirements.txt

# Expose port 5000
EXPOSE 5000

# Start the Flask application
CMD ["python", "app.py"]

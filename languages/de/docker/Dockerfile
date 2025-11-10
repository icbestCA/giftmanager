# Use the official Python 3.11 Alpine image
FROM python:3.11-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install Docker dependencies
RUN apk add --no-cache \
    curl \
    bash \
    docker-cli

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port that the app will run on
EXPOSE 5000

# Command to run the application with Gunicorn
CMD ["gunicorn", "app:app", "-w", "1", "--threads", "4", "-b", "0.0.0.0:5000"]

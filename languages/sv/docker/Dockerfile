# Use the official Python 3.11 Alpine image
FROM python:3.11-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port that the app will run on
EXPOSE 5000

# Allows user to customize threads and bind inside the container
ENV GUNICORN_THREADS=4
ENV GUNICORN_BIND=0.0.0.0:5000

# Command to run the application with Gunicorn and selected parameters
CMD gunicorn app:app --workers 1 --threads ${GUNICORN_THREADS} --bind ${GUNICORN_BIND}
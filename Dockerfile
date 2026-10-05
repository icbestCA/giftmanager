# Use the official Python 3.11 Alpine image
FROM python:3.11-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# .env, users.json, ideas.json and Secret Santa files live here (mounted as a volume)
ENV DATA_DIR=/app/data

# Set the working directory in the container
WORKDIR /app

# Install dependencies first to take advantage of layer caching
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code (see .dockerignore for excluded local data)
COPY app/ /app/

# Expose the port that the app will run on
EXPOSE 5000

# Command to run the application with Gunicorn
CMD ["gunicorn", "app:app", "-w", "1", "--threads", "4", "-b", "0.0.0.0:5000"]

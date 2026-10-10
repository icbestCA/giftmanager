# Build stage: compile the Tailwind CSS bundle into src/static/css/app.css
FROM node:20-alpine AS frontend-build

WORKDIR /frontend

# Install dependencies from the lockfile for reproducible builds
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Build the CSS (outputs to ../src/static/css/app.css)
COPY frontend/input.css frontend/tailwind.config.js ./
RUN npm run build

# Use the official Python 3.11 Alpine image
FROM python:3.11-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Install uv
RUN pip install --no-cache-dir uv

# Copy the dependency manifests and install dependencies from pyproject.toml
COPY pyproject.toml uv.lock /app/
RUN uv sync --frozen --no-dev

# Copy the application source into the container at /app
COPY src /app

# Override with the freshly-built Tailwind CSS from the build stage
COPY --from=frontend-build /src/static/css/app.css /app/static/css/app.css

# Expose the port that the app will run on
EXPOSE 5000

# Allows user to customize threads and bind inside the container
ENV GUNICORN_THREADS=4
ENV GUNICORN_BIND=0.0.0.0:5000
ENV PATH="/app/.venv/bin:$PATH"

# Command to run the application with Gunicorn and selected parameters
CMD gunicorn app:app --workers 1 --threads ${GUNICORN_THREADS} --bind ${GUNICORN_BIND}
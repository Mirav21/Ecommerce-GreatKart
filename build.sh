#!/bin/bash

echo "Building Project..."

# Exit immediately if a command exits with a non-zero status
set -o errexit

# Navigate to the backend directory if necessary
# Make sure to adjust this if the script is not inside emp_backend

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --no-input

# Run migrations
echo "Applying database migrations..."
python manage.py migrate

echo "Creating superuser..."

echo "Build completed successfully."
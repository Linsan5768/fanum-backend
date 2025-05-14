#!/bin/bash
set -e

echo "===== Accounting App Deployment Script ====="
echo "Installing Python dependencies..."
pip install flask flask_cors sqlalchemy gunicorn python-dotenv

echo "Checking if database exists..."
if [ ! -f "accounting.db" ]; then
    echo "Database not found, initializing..."
    python init_db.py
else
    echo "Database found."
fi

echo "Creating .env file if not exists..."
if [ ! -f ".env" ]; then
    cat > .env << EOL
# Production environment variables
FLASK_ENV=production
PORT=5002
# Set to 0 for production
DEBUG=0
EOL
    echo ".env file created with default values."
else
    echo ".env file already exists."
fi

echo "Creating start script..."
cat > start.sh << EOL
#!/bin/bash
# Load environment variables
source .env

# Start Gunicorn server
gunicorn --bind 0.0.0.0:\${PORT:-5002} --workers 4 --timeout 120 app:app
EOL

chmod +x start.sh
echo "start.sh created and made executable."

echo "===== Deployment preparation complete! ====="
echo ""
echo "To start the server in production mode, run:"
echo "./start.sh"
echo ""
echo "To deploy with systemd (on Linux), create a service file and enable it."
echo "For more information, see the README.md"

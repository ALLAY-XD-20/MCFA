# 🟩 MCFA - Minecraft Account Checker

[![Python Version](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![GitHub](https://img.shields.io/badge/Author-ALLAY__XD__20-181717?style=flat-square&logo=github)](https://github.com/ALLAY-XD-20)
[![Discord](https://img.shields.io/badge/Support-Discord-7289DA?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/5YsStsgmXA)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

MCFA is a powerful Minecraft account checker that verifies Microsoft and Mojang accounts, fetches Hypixel stats, checks ban status, retrieves cape and account data, and supports multi-threaded checking with full Discord webhook integration.

---

## ⚙️ Features

- ✅ Microsoft/Xbox/Mojang login authentication
- ✅ Hypixel ban & stat checker
- ✅ OptiFine + Minecraft capes
- ✅ Game Pass / Java / Bedrock / XGPU checker
- ✅ SFA, MFA, 2FA detection
- ✅ Auto proxy scraping + HTTP/SOCKS4/SOCKS5 support
- ✅ Discord webhook notifications
- ✅ Real-time stats, CPM, retries
- ✅ Full config customization via `config.ini`

---

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/ALLAY-XD-20/MCFA.git
cd MCFA
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

[![Download](https://img.shields.io/badge/📥-Download_Latest-success?style=for-the-badge)](https://github.com/ALLAY-XD-20/MCFA/releases/latest)
[![Clone](https://img.shields.io/badge/📋-Clone_Repository-blue?style=for-the-badge)](https://github.com/ALLAY-XD-20/MCFA.git)

### 3. Project Structure

```
MCFA/
├── main.py                 # Main checker file
├── combos/                 # Put your email:pass combos here
│   └── combos1.txt         # Example combo file
├── results/                # Auto-created folder for output logs
│   └── combos1/            # Output for that combo batch
│       ├── Hits.txt
│       ├── Capture.txt
│       ├── Banned.txt
│       └── ...
├── config.ini              # Generated after first run
└── README.md               # This file
```

---

## 🧾 Example Input (Combos)

Put combos in `.txt` files inside the `combos/` folder.

**Example** (`combos/combos1.txt`):
```
email1@example.com:pass123
email2@gmail.com:password456
```

---

## ▶️ How to Run

```bash
python main.py
```

[![Run Now](https://img.shields.io/badge/▶️-Run_Now-success?style=for-the-badge)](main.py)
[![Configuration](https://img.shields.io/badge/⚙️-Edit_Config-blue?style=for-the-badge)](config.ini)

You'll be asked:

1. **🔢 Threads** — (e.g., 100)

2. **🌐 Proxy Type**
   - [![HTTP](https://img.shields.io/badge/1-HTTP-orange?style=flat-square)](#)
   - [![SOCKS4](https://img.shields.io/badge/2-SOCKS4-blue?style=flat-square)](#)
   - [![SOCKS5](https://img.shields.io/badge/3-SOCKS5-green?style=flat-square)](#)
   - [![NONE](https://img.shields.io/badge/4-NONE-red?style=flat-square)](#)
   - [![Auto Scraper](https://img.shields.io/badge/5-Auto_Scraper-purple?style=flat-square)](#)

3. **🖥 Display Mode**
   - [![UI Mode](https://img.shields.io/badge/1-UI_Mode-success?style=flat-square)](#)
   - [![Log Mode](https://img.shields.io/badge/2-Log_Mode-info?style=flat-square)](#)

---

## 📤 Output Files (with Examples)

All results go to `results/<combo_folder>/`

| File Name | Description |
|-----------|-------------|
| `Hits.txt` | ✅ Valid Minecraft accounts |
| `Capture.txt` | 🧠 Full account data (UUID, name, stats) |
| `2fa.txt` | 🔐 Accounts protected with 2FA |
| `MFA.txt` / `SFA.txt` | 📧 Email access level |
| `Banned.txt` | 🚫 Hypixel banned |
| `Unbanned.txt` | ✅ Hypixel clean |
| `Valid_Mail.txt` | 📬 Valid MS login but no MC license |
| `XboxGamePass.txt` | 🎮 Game Pass for PC |
| `XboxGamePassUltimate.txt` | 🏆 XGPU Ultimate accounts |
| `Other.txt` | 🌀 Bedrock / Dungeons / Legends accounts |

### Example from `Capture.txt`:

```
Email: email1@example.com
Password: pass123
Name: SteveMC
Capes: Migrator
Account Type: Xbox Game Pass
Hypixel: Yes
Hypixel Level: 54
First Hypixel Login: Jan 01, 2021
Last Hypixel Login: Mar 12, 2024
Optifine Cape: Yes
Email Access: True
Hypixel Skyblock Coins: 2.3M
Hypixel Bedwars Stars: 16
Hypixel Banned: False
Can Change Name: True
Last Name Change: 2 years - 01/01/2022 - 2022-01-01T14:21:33.124Z
```

---

## ⚙️ Configuration File (config.ini)

`config.ini` is generated automatically on first run.

### 🔧 Editable Sections:

```ini
[Settings]
Webhook = https://discord.com/api/webhooks/...
Max Retries = 5
Proxyless Ban Check = False
WebhookMessage = @everyone HIT: ||<email>:<password>|| ...

[Captures]
Hypixel Name = True
Hypixel Level = True
First Hypixel Login = True
Last Hypixel Login = True
Optifine Cape = True
Minecraft Capes = True
Email Access = True
Hypixel Skyblock Coins = True
Hypixel Bedwars Stars = True
Hypixel Ban = True
Name Change Availability = True
Last Name Change = True
```

### 📩 Webhook Message Placeholders

You can use the following in your webhook message:

- `<email>` – Account email
- `<password>` – Password
- `<name>` – Username
- `<capes>` – Cape types
- `<type>` – Account type (e.g., XGPU, Java)
- `<hypixel>`, `<level>`, `<firstlogin>`, `<lastlogin>`
- `<banned>`, `<access>`, `<skyblockcoins>`, `<bedwarsstars>`
- `<namechange>`, `<lastchanged>`

---

## 🧠 How the Checker Works

1. **Reads combos** from `combos/` folder.
2. **Authenticates** with Microsoft → Xbox → Minecraft APIs.
3. **Checks entitlements** for Java, Bedrock, Game Pass.
4. **Fetches profile data**: UUID, name, cape info.
5. **Scrapes Hypixel stats** using Plancke.io and Shiiyu.moe.
6. **Performs ban detection** on Hypixel Alpha server.
7. **Captures extra info**: 2FA, MFA, SFA, access type.
8. **Saves results** in `results/` and optionally sends webhook alerts.

---

## 🔘 Quick Access

[![Configuration](https://img.shields.io/badge/⚙️-Configuration-blue?style=for-the-badge)](config.ini)
[![Input Folder](https://img.shields.io/badge/📁-Input_Folder-green?style=for-the-badge)](combos/)
[![Results](https://img.shields.io/badge/📊-Results-orange?style=for-the-badge)](results/)
[![Discord Support](https://img.shields.io/badge/💬-Discord_Support-7289DA?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/5YsStsgmXA)

---

## 👤 Developer

[![GitHub](https://img.shields.io/badge/GitHub-ALLAY__XD__20-181717?style=for-the-badge&logo=github)](https://github.com/ALLAY-XD-20)
[![Discord](https://img.shields.io/badge/Discord-Support_Server-7289DA?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/5YsStsgmXA)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

---

## ⚠️ Disclaimer

This tool is for educational and testing purposes only. Users are responsible for ensuring they comply with all applicable terms of service and laws. The developer is not responsible for any misuse of this software.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

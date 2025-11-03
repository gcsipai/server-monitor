# OpenVPN Szerver Konfiguráció és Monitorozás 🛡️📡

## gcsipai/OpenVPNServer

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Shell Script](https://img.shields.io/badge/Telepítés-Bash%20Shell-yellowgreen.svg)](https://www.gnu.org/software/bash/)
[![Web Interface](https://img.shields.io/badge/Monitorozás-PHP-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![OpenVPN](https://img.shields.io/badge/VPN-OpenVPN-red?logo=openvpn&logoColor=white)](https://openvpn.net/)

---

## 💡 Áttekintés

Ez a repozitórium **automatizált telepítő szkripteket** ⚙️ kínál az **OpenVPN szerver** gyors beállításához, amelyet egy egyszerű **PHP alapú webes felület** 🌐 egészít ki a szerver állapotának valós idejű megtekintésére. A projekt minimalista megoldást nyújt a VPN szerver adminisztrációs adatok böngészőből történő elérésére.

---

## 💻 Technológiai Stílus és Fájlarchitektúra

A projekt a VPN szerver telepítését **Bash Shell szkriptekkel** (98.2%) automatizálja, míg a monitorozást **PHP** (1.8%) alapú webszkriptekkel valósítja meg.

| Kategória | Fájl neve | Nyelv/Technológia | Szerep | Emojis/Ico-k |
| :--- | :--- | :--- | :--- | :--- |
| **Szerver Setup** | `debian13-ubuntu24-openvpn-1.1-install.sh` | Bash Shell 🐚 | **Core Telepítés** 📦: OpenVPN beállítása Debian 13 és Ubuntu 24 rendszereken. | 🐧, 🛠️ |
| **Teljes Stack** | `debian13-openvpnweb-6.0-install.sh` | Bash Shell 🐚 | **Web/VPN Telepítés** 🖥️: OpenVPN és a webes kezelőfelület (Web v6.0) beállítása. | 🌐, ✅ |
| **Webes Interfész** | `index.php` | PHP | **Főoldal** 📄: A webes monitorozó felület belépési pontja. | 🏠, ✨ |
| **Monitorozás** | `vpn_status.php` | PHP + OpenVPN API | **Állapotlekérdezés** 📊: Elemzi az OpenVPN szerver **státuszfájlját** (vagy Management Console kimenetét) és megjeleníti a kliensek/forgalom adatait. | 📈, 🚦 |
| **Web Config** | `config.php` | PHP | **Konfiguráció** 🔑: Tartalmazza a webes felület működéséhez szükséges útvonalakat és beállításokat. | 🔧, 🗃️ |

---

## ✨ Főbb Funkciók és Célzott Operációs Rendszerek

### 1. **OpenVPN Adatok Elemzése (PHP)**

A `vpn_status.php` fájl célja, hogy **gépi úton olvasható formátumba** dolgozza fel az OpenVPN szerver **státusz adatkimenetét** (például a `status.log` vagy Management Interface outputját), így téve lehetővé a **böngésző alapú vizualizációt** az aktuális VPN kapcsolatokról. 👁️‍🗨️

### 2. **Támogatott Rendszerek**

A szkriptek kifejezetten a legújabb LTS (Long-Term Support) szerver disztribúciókra fókuszálnak, biztosítva a modern környezetek támogatását. 🎯

| Platform | Verzió | Megjegyzés | Ico |
| :--- | :--- | :--- | :--- |
| **Debian** | **13 (Trixie)** | A legújabb stabil verzió célzott támogatása. | 🔵 |
| **Ubuntu** | **24.04+ (Noble Numbat)** | A 2024-es LTS verzió és újabbak támogatása. | 🟠 |

---

## 🚀 Használat

A telepítéshez válassza ki a megfelelő Shell szkriptet a szerver operációs rendszerének és a kívánt funkcionalitásnak megfelelően.

```bash
# Adjon futtatási jogosultságot
chmod +x debian13-ubuntu24-openvpn-1.1-install.sh

# Indítsa el a telepítést
sudo ./debian13-openvpnweb-6.0-install.sh

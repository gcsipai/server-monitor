# OpenVPN Szerver Konfiguráció és Kliens Letöltés 🛡️🔑

## gcsipai/OpenVPNServer - Automatizált telepítés és OVPN letöltő

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Shell Script](https://img.shields.io/badge/Telepítés-Bash%20Shell-yellowgreen.svg)](https://www.gnu.org/software/bash/)
[![OpenVPN](https://img.shields.io/badge/VPN-OpenVPN-red?logo=openvpn&logoColor=white)](https://openvpn.net/)
[![Web Interface](https://img.shields.io/badge/Letöltő-PHP-777BB4?logo=php&logoColor=white)](https://www.php.net/)

---

## 💡 Áttekintés

Ez a repozitórium **Bash Shell szkripteket** 🐚 biztosít az **OpenVPN szerver** 🔑 gyors telepítéséhez **Debian** és **Ubuntu** rendszereken. A projekt különlegessége egy minimalista **PHP alapú webes felület** 🌐, amelynek célja a **kliens konfigurációs fájlok (.ovpn)** egyszerű létrehozása és letöltése. Ezáltal a felhasználók könnyen hozzáférhetnek a csatlakozáshoz szükséges beállításokhoz.

---

## 💻 Technológiai Komponensek és Fájlarchitektúra

A projekt főleg Shell szkriptekből áll (98.2%), kiegészítve 1.8% PHP kóddal a webes segédfunkciókhoz.

| Fájl neve | Típus | Fő Funkció | Célzott OS / Verzió | Ico |
| :--- | :--- | :--- | :--- | :--- |
| **`debian13-ubuntu24-openvpn-1.1-install.sh`** | **Core Szkript** ⚙️ | **Csak OpenVPN Szerver telepítés:** Gyors, tiszta VPN beállítás webes felület nélkül. | **Debian 13**, **Ubuntu 24.04+** | 🐧, 📡 |
| **`debian13-openvpnweb-6.0-install.sh`** | **Full Stack Szkript** | **VPN + Webes Letöltő telepítés:** OpenVPN és a kapcsolódó PHP webes eszköz beállítása. | **Debian 13** | 🌐, 🖥️ |
| **`index.php`** | PHP | **Kliens Letöltő Felület** ⬇️: Valószínűleg a generált OVPN fájlok letöltési pontja. | N/A | 📄, ✨ |
| **`vpn_status.php`** | PHP | **Szerver Státusz / Utility** 🚦: Bár valószínűbb a konfiguráció letöltés, ez a fájl utalhat a szerver alapvető állapotának ellenőrzésére vagy a konfigurációk listázására. | N/A | 📈, 👁️ |
| **`config.php`** | PHP | **Web Konfiguráció** 🔑: Tartalmazza a webes felület működéséhez szükséges útvonalakat és beállításokat (pl. tanúsítványok helye). | N/A | 🔧, 🗃️ |

---

## ✨ Telepítési Forgatókönyvek

A szkriptek két fő felhasználási forgatókönyvet támogatnak:

| Forgatókönyv | Leírás | Használt Szkript | Eredmény |
| :--- | :--- | :--- | :--- |
| **1. Core VPN Telepítés** | Egyszerű OpenVPN szerver beállítása, **webes letöltő funkció nélkül**. | `debian13-ubuntu24-openvpn-1.1-install.sh` | Gyorsan működő VPN, tiszta szerver környezet. ⚡ |
| **2. VPN + Webes Letöltő** | OpenVPN telepítése kiegészítve a **PHP alapú webes felülettel** a kliens OVPN fájlok kényelmes elosztásához. | `debian13-openvpnweb-6.0-install.sh` | Teljes megoldás a tanúsítványok egyszerű elérésével. ✅ |

---

## 🚀 Használat

Válassza ki a céljának megfelelő szkriptet, adja meg a futtatási jogot, majd indítsa el a telepítést.

```bash
# Core VPN Telepítés Debian 13 / Ubuntu 24 rendszereken
sudo chmod +x debian13-ubuntu24-openvpn-1.1-install.sh
sudo ./debian13-ubuntu24-openvpn-1.1-install.sh

# VPN + Webes Letöltő telepítése Debian 13-ra
sudo chmod +x debian13-openvpnweb-6.0-install.sh
sudo ./debian13-openvpnweb-6.0-install.sh

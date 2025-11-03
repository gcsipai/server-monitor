# OpenVPN Szerver Telepítés és Kliens Konfiguráció Letöltés 🛡️🔑

## gcsipai/OpenVPNServer - Automatizált VPN beállítás és OVPN fájlkezelés

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Bash Shell](https://img.shields.io/badge/Telepítés-Bash%20Shell-yellowgreen.svg)](https://www.gnu.org/software/bash/)
[![OpenVPN](https://img.shields.io/badge/VPN-OpenVPN-red?logo=openvpn&logoColor=white)](https://openvpn.net/)
[![PHP Utility](https://img.shields.io/badge/Utility-PHP-777BB4?logo=php&logoColor=white)](https://www.php.net/)

---

## 💡 Áttekintés

Ez a repozitórium **Bash Shell szkripteket** 🐚 biztosít az **OpenVPN szerver** 🔑 gyors telepítéséhez **Debian** és **Ubuntu** szervereken.

A projekt tartalmaz egy kiegészítő **PHP webes segédprogramot** 🌐, amelynek **elsődleges funkciója** a kliensek számára generált **OpenVPN konfigurációs fájlok (.ovpn)** egyszerű letöltése. Ez a megoldás nagymértékben leegyszerűsíti a kliensek beállítását.

---

## 💻 Technológiai Komponensek és Fájlarchitektúra

A projekt főleg Shell szkriptekből (98.2%) áll az automatizáláshoz, kiegészítve PHP (1.8%) fájlokkal a webes kényelmi funkciókhoz.

| Fájl neve | Típus | Fő Funkció | Támogatott OS / Verzió | Ico |
| :--- | :--- | :--- | :--- | :--- |
| **`debian13-ubuntu24-openvpn-1.1-install.sh`** | **Core Szkript** ⚙️ | **Alap VPN Telepítés:** Tisztán OpenVPN szerver beállítása, **webes komponensek nélkül**. | **Debian 13**, **Ubuntu 24.04+** | 🐧, 📡 |
| **`debian13-openvpnweb-6.0-install.sh`** | **Webes Szkript** | **VPN + Letöltő Telepítés:** OpenVPN szerver és a kapcsolódó PHP webes eszköz beállítása. | **Debian 13** | 🌐, 🖥️ |
| **`index.php`** | PHP | **Letöltő Felület** ⬇️: A generált OVPN fájlok letöltési pontja. | N/A | 📄, ✨ |
| **`vpn_status.php`** | PHP | **Utility fájl** 🗃️: Valószínűleg a konfigurációs fájlok kezeléséhez vagy az aktuális állapot **korlátozott** ellenőrzéséhez használt segédszkript. | N/A | 📈, 🔧 |
| **`config.php`** | PHP | **Webes Konfiguráció** 🔑: A PHP felület működéséhez szükséges útvonalak és beállítások tárolása. | N/A | 🔒, 🛠️ |

---

## ✨ Telepítési Forgatókönyvek

A szkriptek két egyértelmű felhasználási forgatókönyvet kínálnak:

| Forgatókönyv | Leírás | Használt Szkript | Előny |
| :--- | :--- | :--- | :--- |
| **1. Tiszta VPN Telepítés** | Egyszerű OpenVPN szerver beállítása, ha a konfigurációs fájlokat **kézzel** kezeli. | `debian13-ubuntu24-openvpn-1.1-install.sh` | Minimalista, nagy teljesítményű VPN környezet. ⚡ |
| **2. VPN Kliens Letöltővel** | OpenVPN telepítése a **PHP webes felülettel** kiegészítve, ami megkönnyíti a kliens OVPN fájlok elosztását. | `debian13-openvpnweb-6.0-install.sh` | Kényelmes megoldás a felhasználók számára. ✅ |

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

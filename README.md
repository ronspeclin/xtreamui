# Xtream UI Installer

This script installs Xtream UI for IPTV on Ubuntu 20.04 LTS.

## Prerequisites

- Ubuntu 20.04 LTS
- Python 3 installed

## Installation

Open your terminal and run the following commands:

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt-get install dirmngr -y
sudo apt install python3 -y
sudo apt install python2 -y
rm xtreamui_install.py
wget https://raw.githubusercontent.com/ronspeclin/xtreamui/main/xtreamui_install.py
sudo python3 xtreamui_install.py

#!/usr/bin/python3
# -*- coding: utf-8 -*-
import subprocess, os, random, string, sys, shutil, socket, zipfile, urllib.request, json, base64
from itertools import cycle, zip_longest as izip
from zipfile import ZipFile
from urllib.request import Request, urlopen, URLError, HTTPError

rDownloadURL = {"main": "https://bitbucket.org/le_lio/assets/raw/master/main_xui_neyslim.tar.gz", "sub": "https://bitbucket.org/le_lio/assets/raw/master/sub_xui_neyslim.tar.gz"}
rPackages = ["libcurl4", "libxslt1-dev", "libgeoip-dev", "e2fsprogs", "wget", "mcrypt", "nscd", "htop", "zip", "unzip", "mc", "libpng16-16", "libzip5", "python-is-python2", "mariadb-server"]
rInstall = {"MAIN": "main", "LB": "sub"}
rUpdate = {"ADMIN": "admin"}
rMySQLCnf = base64.b64decode(b"IyBYdHJlYW0gQ29kZXMKCltjbGllbnRdCnBvcnQgICAgICAgICAgICA9IDMzMDYKCltteXNxbGRfc2FmZV0KbmljZSAgICAgICAgICAgID0gMAoKW215c3FsZF0KdXNlciAgICAgICAgICAgID0gbXlzcWwKcG9ydCAgICAgICAgICAgID0gNzk5OQpiYXNlZGlyICAgICAgICAgPSAvdXNyCmRhdGFkaXIgICAgICAgICA9IC92YXIvbGliL215c3FsCnRtcGRpciAgICAgICAgICA9IC90bXAKbGMtbWVzc2FnZXMtZGlyID0gL3Vzci9zaGFyZS9teXNxbApza2lwLWV4dGVybmFsLWxvY2tpbmcKc2tpcC1uYW1lLXJlc29sdmU9MQoKYmluZC1hZGRyZXNzICAgICAgICAgICAgPSAqCmtleV9idWZmZXJfc2l6ZSA9IDEyOE0KCm15aXNhbV9zb3J0X2J1ZmZlcl9zaXplID0gNE0KbWF4X2FsbG93ZWRfcGFja2V0ICAgICAgPSA2NE0KbXlpc2FtLXJlY292ZXItb3B0aW9ucyA9IEJBQ0tVUAptYXhfbGVuZ3RoX2Zvcl9zb3J0X2RhdGEgPSA4MTkyCnF1ZXJ5X2NhY2hlX2xpbWl0ICAgICAgID0gNE0KcXVlcnlfY2FjaGVfc2l6ZSAgICAgICAgPSAwCnF1ZXJ5X2NhY2hlX3R5cGUJPSAwCgpleHBpcmVfbG9nc19kYXlzICAgICAgICA9IDEwCm1heF9iaW5sb2dfc2l6ZSAgICAgICAgID0gMTAwTQoKbWF4X2Nvbm5lY3Rpb25zICA9IDIwMDAgI3JlY29tbWVuZGVkIGZvciAxNkdCIHJhbSAKYmFja19sb2cgPSA0MDk2Cm9wZW5fZmlsZXNfbGltaXQgPSAxNjM4NAppbm5vZGJfb3Blbl9maWxlcyA9IDE2Mzg0Cm1heF9jb25uZWN0X2Vycm9ycyA9IDMwNzIKdGFibGVfb3Blbl9jYWNoZSA9IDQwOTYKdGFibGVfZGVmaW5pdGlvbl9jYWNoZSA9IDQwOTYKCgp0bXBfdGFibGVfc2l6ZSA9IDFHCm1heF9oZWFwX3RhYmxlX3NpemUgPSAxRwoKaW5ub2RiX2J1ZmZlcl9wb29sX3NpemUgPSAxMkcgI3JlY29tbWVuZGVkIGZvciAxNkdCIHJhbQppbm5vZGJfYnVmZmVyX3Bvb2xfaW5zdGFuY2VzID0gMQppbm5vZGJfcmVhZF9pb190aHJlYWRzID0gNjQKaW5ub2RiX3dyaXRlX2lvX3RocmVhZHMgPSA2NAppbm5vZGJfdGhyZWFkX2NvbmN1cnJlbmN5ID0gMAppbm5vZGJfZmx1c2hfbG9nX2F0X3RyeF9jb21taXQgPSAwCmlubm9kYl9mbHVzaF9tZXRob2QgPSBPX0RJUkVDVApwZXJmb3JtYW5jZV9zY2hlbWEgPSBPTgppbm5vZGItZmlsZS1wZXItdGFibGUgPSAxCmlubm9kYl9pb19jYXBhY2l0eT0yMDAwMAppbm5vZGJfdGFibGVfbG9ja3MgPSAwCmlubm9kYl9sb2NrX3dhaXRfdGltZW91dCA9IDAKaW5ub2RiX2RlYWRsb2NrX2RldGVjdCA9IDAKaW5ub2RiX2xvZ19maWxlX3NpemUgPSA1MTJNCgpzcWwtbW9kZT0iTk9fRU5HSU5FX1NVQlNUSVRVVElPTiIKCltteXNxbGR1bXBdCnF1aWNrCnF1b3RlLW5hbWVzCm1heF9hbGxvd2VkX3BhY2tldCAgICAgID0gMTZNCgpbbXlzcWxdCgpbaXNhbWNoa10Ka2V5X2J1ZmZlcl9zaXplICAgICAgICAgICAgICA9IDE2TQo=")


class col:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    YELLOW = '\033[33m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def generate(length=19): return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(length))


def getIP():
    import socket
    import requests

    services = [
        'http://ip.42.pl/raw',
        'http://ipecho.net/plain',
        'http://checkip.amazonaws.com/'
    ]
    
    for service in services:
        try:
            response = requests.get(service)
            if response.status_code == 200:
                return response.text.strip()
        except requests.RequestException:
            pass
    
    try:
        # If all services fail, use a fallback method
        ip = socket.gethostbyname(socket.gethostname())
        return ip
    except Exception:
        return "127.0.0.1"

def getVersion():
    try: return subprocess.check_output("lsb_release -d".split()).split(b":")[-1].strip().decode('utf-8')
    except: return ""

def printc(rText, rColour=col.OKBLUE, rPadding=0):
    max_length = 52  # Max length of text to fit within the box
    lines = [rText[i:i+max_length] for i in range(0, len(rText), max_length)]

    print("%s ┌%s┐ %s" % (rColour, "─" * (max_length + 2), col.ENDC))
    for i in range(rPadding):
        print("%s │%s│ %s" % (rColour, " " * (max_length + 2), col.ENDC))
    
    for line in lines:
        print("%s │ %s%s │ %s" % (rColour, line, " " * (max_length - len(line)), col.ENDC))
    
    for i in range(rPadding):
        print("%s │%s│ %s" % (rColour, " " * (max_length + 2), col.ENDC))
    
    print("%s └%s┐ %s" % (rColour, "─" * (max_length + 2), col.ENDC))
    print(" ")


def prepare(rType="MAIN"):
    global rPackages
    if rType != "MAIN": rPackages = rPackages[:-1]
    printc("Preparing Installation")
    if os.path.isfile('/home/xtreamcodes/iptv_xtream_codes/config'):
        shutil.copyfile('/home/xtreamcodes/iptv_xtream_codes/config', '/tmp/config.xtmp')
    os.system('chattr -i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null')
    for rFile in ["/var/lib/dpkg/lock-frontend", "/var/cache/apt/archives/lock", "/var/lib/dpkg/lock"]:
        try: os.remove(rFile)
        except: pass
    os.system("apt-get update > /dev/null")
    os.system("apt-get -y full-upgrade > /dev/null")
    if rType == "MAIN":

        printc("Install MariaDB 10.5 repository")
        os.system("apt-get install -y software-properties-common > /dev/null")
        os.system("apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8 >/dev/null 2>&1")
        os.system("add-apt-repository 'deb [arch=amd64,arm64,ppc64el] http://ams2.mirrors.digitalocean.com/mariadb/repo/10.5/ubuntu focal main'  > /dev/null")
        os.system("apt-get update > /dev/null")
    for rPackage in rPackages:
        printc("Installing %s" % rPackage)
        os.system("apt-get install %s -y > /dev/null" % rPackage)
    printc("Installing pip2 and python2 paramiko")
    os.system("add-apt-repository universe > /dev/null 2>&1 && curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py > /dev/null 2>&1 && python2 get-pip.py > /dev/null 2>&1 && pip2 install paramiko > /dev/null 2>&1")
    os.system("apt-get install -f > /dev/null") # Clean up above
    try:
        subprocess.check_output("getent passwd xtreamcodes > /dev/null".split())
    except:
        # Create User
        printc("Creating user xtreamcodes")
        os.system("adduser --system --shell /bin/false --group --disabled-login xtreamcodes > /dev/null")
    if not os.path.exists("/home/xtreamcodes"): os.mkdir("/home/xtreamcodes")
    return True

def install(rType="MAIN"):
    global rInstall, rDownloadURL
    printc("Downloading Software")
    try: rURL = rDownloadURL[rInstall[rType]]
    except:
        printc("Invalid download URL!", col.FAIL)
        return False
    os.system('wget -q -O "/tmp/xtreamcodes.tar.gz" "%s"' % rURL)
    if os.path.exists("/tmp/xtreamcodes.tar.gz"):
        printc("Installing Software")
        os.system('tar -zxvf "/tmp/xtreamcodes.tar.gz" -C "/home/xtreamcodes/" > /dev/null')
        try: os.remove("/tmp/xtreamcodes.tar.gz")
        except: pass
        return True
    printc("Failed to download installation file!", col.FAIL)
    return False

def update(rType="MAIN"):

    rlink ="https://bitbucket.org/le_lio/assets/raw/master/release_22f.zip"
    hdr = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36',
       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
       'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
       'Accept-Encoding': 'none',
       'Accept-Language': 'en-US,en;q=0.8',
       'Connection': 'keep-alive'}
    req = Request(rlink, headers=hdr)
    try:
        urlopen(req)
    except:
        printc("Invalid download URL!", col.FAIL)
        return False
    print("\n")
    rURL = rlink
    printc("Downloading Software Update")
    print("\n")
    os.system('wget -q -O "/tmp/update.zip" "%s"' % rURL)
    if os.path.exists("/tmp/update.zip"):
        try: is_ok = zipfile.ZipFile("/tmp/update.zip")
        except:
            printc("Invalid link or zip file is corrupted!", col.FAIL)
            os.remove("/tmp/update.zip")
            return False
        printc("Updating Software")
        os.system('chattr -i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null && rm -rf /home/xtreamcodes/iptv_xtream_codes/admin > /dev/null && rm -rf /home/xtreamcodes/iptv_xtream_codes/pytools > /dev/null && unzip /tmp/update.zip -d /tmp/update/ > /dev/null && cp -rf /tmp/update/XtreamUI-master/* /home/xtreamcodes/iptv_xtream_codes/ > /dev/null && rm -rf /tmp/update/XtreamUI-master > /dev/null && rm -rf /tmp/update > /dev/null && chown -R xtreamcodes:xtreamcodes /home/xtreamcodes/ > /dev/null && chmod +x /home/xtreamcodes/iptv_xtream_codes/permissions.sh > /dev/null && chattr +i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null')
        if not "sudo chmod 400 /home/xtreamcodes/iptv_xtream_codes/config" in open("/home/xtreamcodes/iptv_xtream_codes/permissions.sh").read(): os.system('echo "#!/bin/bash\nsudo chmod -R 777 /home/xtreamcodes 2>/dev/null\nsudo find /home/xtreamcodes/iptv_xtream_codes/admin/ -type f -exec chmod 644 {} \; 2>/dev/null\nsudo find /home/xtreamcodes/iptv_xtream_codes/admin/ -type d -exec chmod 755 {} \; 2>/dev/null\nsudo find /home/xtreamcodes/iptv_xtream_codes/wwwdir/ -type f -exec chmod 644 {} \; 2>/dev/null\nsudo find /home/xtreamcodes/iptv_xtream_codes/wwwdir/ -type d -exec chmod 755 {} \; 2>/dev/null\nsudo chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx 2>/dev/null\nsudo chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp 2>/dev/null\nsudo chmod 400 /home/xtreamcodes/iptv_xtream_codes/config 2>/dev/null" > /home/xtreamcodes/iptv_xtream_codes/permissions.sh')
        os.system("/home/xtreamcodes/iptv_xtream_codes/permissions.sh > /dev/null")
        try: os.remove("/tmp/update.zip")
        except: pass
        return True
    printc("Failed to download installation file!", col.FAIL)
    return False

def mysql(rUsername, rPassword):
    global rMySQLCnf
    printc("Configuring MySQL")
    rCreate = True
    if os.path.exists("/etc/mysql/my.cnf"):
        with open("/etc/mysql/my.cnf", "r") as file:
            if file.read(14) == "# Xtream Codes":
                rCreate = False
    if rCreate:
        shutil.copy("/etc/mysql/my.cnf", "/etc/mysql/my.cnf.xc")
        with open("/etc/mysql/my.cnf", "w") as rFile:
            rFile.write(rMySQLCnf.decode('utf-8'))  # Decode the bytes to string here
        os.system("systemctl restart mariadb > /dev/null")
    
    for i in range(5):
        rMySQLRoot = ""  # input("Enter MySQL Root Password: ")
        print(" ")
        rExtra = f" -p{rMySQLRoot}" if len(rMySQLRoot) > 0 else ""
        printc("Drop existing & create database? Y/N", col.WARNING)
        rDrop = input("  ").upper() == "Y"
        try:
            if rDrop:
                os.system(f'mysql -u root{rExtra} -e "DROP DATABASE IF EXISTS xtream_iptvpro; CREATE DATABASE IF NOT EXISTS xtream_iptvpro;" > /dev/null')
                os.system(f'mysql -u root{rExtra} -e "USE xtream_iptvpro; DROP USER IF EXISTS \'{rUsername}\'@\'%\';" > /dev/null')
                os.system(f"mysql -u root{rExtra} xtream_iptvpro < /home/xtreamcodes/iptv_xtream_codes/database.sql > /dev/null")
                os.system(f'mysql -u root{rExtra} -e "USE xtream_iptvpro; UPDATE settings SET live_streaming_pass = \'{generate(20)}\', unique_id = \'{generate(10)}\', crypt_load_balancing = \'{generate(20)}\';" > /dev/null')
                os.system(f'''mysql -u root{rExtra} -e "USE xtream_iptvpro; 
                REPLACE INTO streaming_servers 
                (id, server_name, domain_name, server_ip, vpn_ip, ssh_password, ssh_port, diff_time_main, 
                http_broadcast_port, total_clients, system_os, network_interface, latency, status, enable_geoip, 
                geoip_countries, last_check_ago, can_delete, server_hardware, total_services, persistent_connections, 
                rtmp_port, geoip_type, isp_names, isp_type, enable_isp, boost_fpm, http_ports_add, network_guaranteed_speed, 
                https_broadcast_port, https_ports_add, whitelist_ips, watchdog_data, timeshift_only) 
                VALUES (1, 'Main Server', '', '{getIP()}', '', NULL, NULL, 0, 25461, 1000, '{getVersion()}', 
                'eth0', 0, 1, 0, '', 0, 0, '{{}}', 3, 0, 25462, 'low_priority', '', 'low_priority', 0, 1, '', 
                1000, 25463, '', '["127.0.0.1",""]', '{{}}', 0);" > /dev/null''')
                os.system(f'''mysql -u root{rExtra} -e "USE xtream_iptvpro; 
                REPLACE INTO reg_users (id, username, password, email, member_group_id, verified, status) 
                VALUES (1, 'admin', 
                '$6$rounds=20000$xtreamcodes$XThC5OwfuS0YwS4ahiifzF14vkGbGsFF1w7ETL4sRRC5sOrAWCjWvQJDromZUQoQuwbAXAFdX3h3Cp3vqulpS0', 
                'admin@website.com', 1, 1, 1);" > /dev/null''')
                os.system(f'''mysql -u root{rExtra} -e "CREATE USER '{rUsername}'@'%' IDENTIFIED BY '{rPassword}'; 
                GRANT ALL PRIVILEGES ON xtream_iptvpro.* TO '{rUsername}'@'%' WITH GRANT OPTION; 
                GRANT SELECT, LOCK TABLES ON *.* TO '{rUsername}'@'%';FLUSH PRIVILEGES;" > /dev/null''')
                os.system(f'''mysql -u root{rExtra} -e "USE xtream_iptvpro; 
                CREATE TABLE IF NOT EXISTS dashboard_statistics 
                (id int(11) NOT NULL AUTO_INCREMENT, type varchar(16) NOT NULL DEFAULT '', time int(16) NOT NULL DEFAULT '0', 
                count int(16) NOT NULL DEFAULT '0', PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=latin1; 
                INSERT INTO dashboard_statistics (type, time, count) VALUES('conns', UNIX_TIMESTAMP(), 0),('users', UNIX_TIMESTAMP(), 0);" > /dev/null''')
            try:
                os.remove("/home/xtreamcodes/iptv_xtream_codes/database.sql")
            except:
                pass
            return True
        except Exception as e:
            printc(f"Invalid password! Try again. Error: {e}", col.FAIL)
    return False



def encrypt(rHost="127.0.0.1", rUsername="user_iptvpro", rPassword="", rDatabase="xtream_iptvpro", rServerID=1, rPort=7999):
    import base64
    if os.path.isfile('/home/xtreamcodes/iptv_xtream_codes/config'):
        rDecrypt = decrypt()
        if rDecrypt:
            rHost = rDecrypt["host"]
            rPassword = rDecrypt["db_pass"]
            rServerID = int(rDecrypt["server_id"])
            rUsername = rDecrypt["db_user"]
            rDatabase = rDecrypt["db_name"]
            rPort = int(rDecrypt["db_port"])
        else:
            printc("Failed to decrypt configuration. Using provided parameters.", col.FAIL)
    printc("Encrypting...")
    try: os.remove("/home/xtreamcodes/iptv_xtream_codes/config")
    except: pass
    data = f'{{"host":"{rHost}","db_user":"{rUsername}","db_pass":"{rPassword}","db_name":"{rDatabase}","server_id":"{rServerID}", "db_port":"{rPort}"}}'
    encrypted_data = bytearray((ord(c) ^ ord(k)) for c, k in zip(data, cycle('5709650b0d7806074842c6de575025b1')))
    encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')
    with open('/home/xtreamcodes/iptv_xtream_codes/config', 'w') as rf:
        rf.write(encrypted_data)



def decrypt():
    import base64
    rConfigPath = "/home/xtreamcodes/iptv_xtream_codes/config"
    try:
        with open(rConfigPath, 'rb') as f:
            encrypted_data = f.read()
        encrypted_data = base64.b64decode(encrypted_data)
        decrypted_data = ''.join(chr(c ^ ord(k)) for c, k in zip(encrypted_data, cycle('5709650b0d7806074842c6de575025b1')))
        return json.loads(decrypted_data)
    except Exception as e:
        print(f"Error decrypting configuration: {e}")
        return None




def configure():
    printc("Configuring System")
    if not "/home/xtreamcodes/iptv_xtream_codes/" in open("/etc/fstab").read():
        rFile = open("/etc/fstab", "a")
        rFile.write("tmpfs /home/xtreamcodes/iptv_xtream_codes/streams tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=90% 0 0\ntmpfs /home/xtreamcodes/iptv_xtream_codes/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=2G 0 0")
        rFile.close()
    if not "xtreamcodes" in open("/etc/sudoers").read():
        os.system('echo "xtreamcodes ALL = (root) NOPASSWD: /sbin/iptables, /usr/bin/chattr, /usr/bin/python2, /usr/bin/python" >> /etc/sudoers')
    if not os.path.exists("/etc/init.d/xtreamcodes"):
        rFile = open("/etc/init.d/xtreamcodes", "w")
        rFile.write("#! /bin/bash\n/home/xtreamcodes/iptv_xtream_codes/start_services.sh")
        rFile.close()
        os.system("chmod +x /etc/init.d/xtreamcodes > /dev/null")
    try: os.remove("/usr/bin/ffmpeg")
    except: pass
    if not os.path.exists("/home/xtreamcodes/iptv_xtream_codes/tv_archive"): os.mkdir("/home/xtreamcodes/iptv_xtream_codes/tv_archive/")
    os.system("ln -s /home/xtreamcodes/iptv_xtream_codes/bin/ffmpeg /usr/bin/")
    os.system("chattr -i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null")
    os.system("wget -q https://bitbucket.org/le_lio/assets/raw/master/GeoLite2.mmdb -O /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb")
    os.system("wget -q https://bitbucket.org/le_lio/assets/raw/master/pid_monitor.php -O /home/xtreamcodes/iptv_xtream_codes/crons/pid_monitor.php")
    os.system("chown xtreamcodes:xtreamcodes -R /home/xtreamcodes > /dev/null")
    os.system("chmod -R 0777 /home/xtreamcodes > /dev/null")
    os.system("chattr +i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null")
    os.system("sed -i 's|chown -R xtreamcodes:xtreamcodes /home/xtreamcodes|chown -R xtreamcodes:xtreamcodes /home/xtreamcodes 2>/dev/null|g' /home/xtreamcodes/iptv_xtream_codes/start_services.sh")
    os.system("chmod +x /home/xtreamcodes/iptv_xtream_codes/start_services.sh > /dev/null")
    os.system("mount -a")
    os.system("chmod 0700 /home/xtreamcodes/iptv_xtream_codes/config > /dev/null")
    os.system("sed -i 's|echo \"Xtream Codes Reborn\";|header(\"Location: https://www.google.com/\");|g' /home/xtreamcodes/iptv_xtream_codes/wwwdir/index.php")
    if not "api.xtream-codes.com" in open("/etc/hosts").read(): os.system('echo "127.0.0.1    api.xtream-codes.com" >> /etc/hosts')
    if not "downloads.xtream-codes.com" in open("/etc/hosts").read(): os.system('echo "127.0.0.1    downloads.xtream-codes.com" >> /etc/hosts')
    if not "xtream-codes.com" in open("/etc/hosts").read(): os.system('echo "127.0.0.1    xtream-codes.com" >> /etc/hosts')
    if not "@reboot root /home/xtreamcodes/iptv_xtream_codes/start_services.sh" in open("/etc/crontab").read(): os.system('echo "@reboot root /home/xtreamcodes/iptv_xtream_codes/start_services.sh" >> /etc/crontab')

def start(first=True):
    if first: printc("Starting Xtream Codes")
    else: printc("Restarting Xtream Codes")
    os.system("/home/xtreamcodes/iptv_xtream_codes/start_services.sh > /dev/null")

def modifyNginx():
    printc("Modifying Nginx")
    rPath = "/home/xtreamcodes/iptv_xtream_codes/nginx/conf/nginx.conf"
    rPrevData = open(rPath, "r").read()
    if not "listen 25500;" in rPrevData:
        shutil.copy(rPath, "%s.xc" % rPath)
        rData = "}".join(rPrevData.split("}")[:-1]) + "    server {\n        listen 25500;\n        index index.php index.html index.htm;\n        root /home/xtreamcodes/iptv_xtream_codes/admin/;\n\n        location ~ \.php$ {\n                    limit_req zone=one burst=8;\n            try_files $uri =404;\n                 fastcgi_index index.php;\n         fastcgi_pass php;\n                      include fastcgi_params;\n                       fastcgi_buffering on;\n                 fastcgi_buffers 96 32k;\n                       fastcgi_buffer_size 32k;\n                      fastcgi_max_temp_file_size 0;\n                 fastcgi_keep_conn on;\n                 fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n                 fastcgi_param SCRIPT_NAME $fastcgi_script_name;\n        }\n    }\n}"
        rFile = open(rPath, "w")
        rFile.write(rData)
        rFile.close()

if __name__ == "__main__":
    printc("Xtream UI 22f MOD Ubuntu 20.04 Installer", col.OKGREEN, 2)
    printc("By: NeySlim/LoferTech/RonSpeclin", col.OKGREEN, 2)

    print(" ")
    rType = input("  Installation Type [MAIN, LB]: ")
    print(" ")
    if rType.upper() in ["MAIN", "LB"]:
        if rType.upper() == "LB":
            rHost = input("  Main Server IP Address: ")
            rPassword = input("  MySQL Password: ")
            try: rServerID = int(input("  Load Balancer Server ID: "))
            except: rServerID = -1
            print(" ")
        else:
            rHost = "127.0.0.1"
            rPassword = generate()
            rServerID = 1
        rUsername = "user_iptvpro"
        rDatabase = "xtream_iptvpro"
        rPort = 7999
        if len(rHost) > 0 and len(rPassword) > 0 and rServerID > -1:
            printc("Start installation? Y/N", col.WARNING)
            if input("  ").upper() == "Y":
                print(" ")
                rRet = prepare(rType.upper())
                if not install(rType.upper()): sys.exit(1)
                if rType.upper() == "MAIN":
                    if not mysql(rUsername, rPassword): sys.exit(1)
                encrypt(rHost, rUsername, rPassword, rDatabase, rServerID, rPort)
                configure()
                if rType.upper() == "MAIN": modifyNginx()
                start()
                printc("Installation completed!", col.OKGREEN, 2)
                if rType.upper() == "MAIN":
                    printc("Please store your MySQL password!")
                    printc(rPassword)
                    printc("Admin UI: http://%s:25500" % getIP())
                    printc("Admin UI default login is admin/admin")
            else: printc("Installation cancelled", col.FAIL)
        else: printc("Invalid entries", col.FAIL)
    else: printc("Invalid installation type", col.FAIL)

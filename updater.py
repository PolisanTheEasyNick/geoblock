import os
import subprocess
import requests
import zipfile
import sqlite3
import struct
import socket
import ipaddress
from datetime import datetime

ZONE_DIR = "/opt/iptables"
IPSET_NAME = "GEO_BLOCK"
DB_URL = "https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.CSV.ZIP"
DB_PATH = "/tmp/IP2LOCATION-LITE-DB1.CSV"
BACKUP_ZONE_DIR = os.path.join(ZONE_DIR, "backup")
SQLITE_DB_PATH = "app.db" 
os.chdir("/opt/hosting/geoblock/")

def check_internet_access():
    while True:
        try:
            subprocess.run(['ping', '-c', '1', '8.8.8.8'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("Internet is accessible.")
            break
        except subprocess.CalledProcessError:
            print("No internet access. Retrying in 5 seconds...")
            time.sleep(5)

def timestamp():
    return subprocess.check_output("date +%Y-%m-%d_%H-%M-%S", shell=True).decode().strip()

def backup_existing_rules():
    if not os.path.exists(BACKUP_ZONE_DIR):
        os.makedirs(BACKUP_ZONE_DIR, exist_ok=True)
    subprocess.run(['sudo', 'iptables-save'], stdout=open(os.path.join(BACKUP_ZONE_DIR, f"iptables_{timestamp()}.backup"), 'w'), check=True)
    subprocess.run(['sudo', 'ipset', 'save'], stdout=open(os.path.join(BACKUP_ZONE_DIR, f"ipset_{timestamp()}.backup"), 'w'), check=True)

def download_and_extract_db():
    print("Downloading and extracting database ...")
    response = requests.get(DB_URL, stream=True)
    with open("/tmp/IP2LOCATION-LITE-DB1.CSV.ZIP", 'wb') as f:
        f.write(response.content)
    
    with zipfile.ZipFile("/tmp/IP2LOCATION-LITE-DB1.CSV.ZIP", 'r') as zip_ref:
        zip_ref.extractall("/tmp/")
    print("Database downloaded and extracted.")

def setup_ipset():
    result = subprocess.run(['sudo', 'ipset', 'list', IPSET_NAME], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        print("Flushing existing ipset set...")
        subprocess.run(['sudo', 'ipset', 'flush', IPSET_NAME], check=True)
    else:
        print("Creating new ipset set...")
        subprocess.run(['sudo', 'ipset', 'create', IPSET_NAME, 'hash:net', 'family', 'inet'], check=True)

def setup_iptables():
    result = subprocess.run(['sudo', 'iptables', '-C', 'INPUT', '-m', 'set', '--match-set', IPSET_NAME, 'src', '-j', 'DROP'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print("Creating new iptables rule...")
        subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '-m', 'set', '--match-set', IPSET_NAME, 'src', '-j', 'DROP'], check=True)
    else:
        print("iptables rule already exists.")

def convert_ip_range_to_cidr(start_ip, end_ip):
    start_ip = ipaddress.ip_address(int(start_ip))
    end_ip = ipaddress.ip_address(int(end_ip))

    network = ipaddress.summarize_address_range(start_ip, end_ip)
    cidr_blocks = [str(net) for net in network]

    return cidr_blocks[0]

def get_from_db(query, params=()):
    with sqlite3.connect(SQLITE_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

def process_country_group(countries):
    with open(DB_PATH, 'r') as db_file:
        for line in db_file:
            parts = line.strip().split(',')
            start_ip, end_ip, country_code = parts[0].strip('"'), parts[1].strip('"'), parts[2].strip('"')
            if country_code in countries:
                #print(f"converting start_ip of {start_ip} and end_ip {end_ip} to CIDR...")
                cidr = convert_ip_range_to_cidr(start_ip, end_ip)
                if cidr:
                    print(f"Adding {cidr} to ipset for {country_code}")
                    subprocess.run(['sudo', 'ipset', 'add', IPSET_NAME, cidr], check=True)

def update():
    check_internet_access()
    backup_existing_rules()
    download_and_extract_db()
    setup_ipset()
    setup_iptables()

    countries = [row[0] for row in get_from_db('SELECT code FROM countries WHERE picked == True')]
    print(f"Countries: {countries}")
    port_protocols = get_from_db('SELECT port_number, protocol FROM port_rules')
    print(f"Ports: {port_protocols}")
    whitelist_ips = [row[0] for row in get_from_db('SELECT cidr FROM whitelisted_ips')]
    print(f"Whitelisted ips: {whitelist_ips}")

    process_country_group(countries)

    for ip in whitelist_ips:
        print(f"Adding whitelisted IP {ip} to iptables with ACCEPT action")
        subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '-s', ip, '-j', 'ACCEPT'], check=True)

    with sqlite3.connect(SQLITE_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM system_info')
        cursor.execute('INSERT INTO system_info (last_update_date) VALUES (?)', (datetime.now().isoformat(),))

    print("Country blocking rules updated.")


if __name__ == "__main__":
    update()

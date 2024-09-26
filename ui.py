import os
import zipfile
import sqlite3
import csv
from flask import Flask, request, render_template_string, redirect, url_for, jsonify
from subprocess import run, CalledProcessError, check_output, Popen, PIPE
import netaddr
from updater import update
import re
import time
from threading import Thread
from datetime import datetime

app = Flask(__name__)
DATABASE = 'app.db'
DB_URL = 'http://www.ipdeny.com/ipblocks/data/countries'
CIDR_PATTERN = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|[12][0-9]|[0-9])$')
update_completed = False

os.chdir("/opt/hosting/geoblock/")
CRON_JOB = '0 5 1,15 * * /usr/bin/python3 /opt/hosting/geoblock/updater.py'

def is_valid_cidr(cidr):
    return CIDR_PATTERN.match(cidr) is not None

def cron_job_exists():
    try:
        result = run(['crontab', '-l'], capture_output=True, text=True, check=True)
        return CRON_JOB in result.stdout
    except CalledProcessError as e:
        return False


#### HTML SECTION ####

# HTML template for the web UI
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Country GEOBLOCK</title>
        <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
        }

        h1, h2 {
            color: #333;
        }

        h1 {
            text-align: center;
            margin-top: 20px;
        }

        h2 {
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }

        details {
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            margin: 20px;
        }

        summary {
            cursor: pointer;
            font-weight: bold;
        }

        input[type="text"], input[type="submit"], select {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }

        input[type="submit"] {
            background-color: #008000;
            color: #fff;
            border: none;
            cursor: pointer;
            font-size: 1em;
        }

        input[type="submit"]:hover {
            background-color: #007000;
        }

        table {
            border-collapse: collapse;
            margin-bottom: 20px;
            background-color: #fff;
        }

        th, td {
            padding: 10px;
            text-align: left;
            border: 1px solid #ddd;
        }

        th {
            background-color: #f4f4f4;
        }

        tr:nth-child(even) {
            background-color: #f9f9f9;
        }

        button {
            padding: 5px 10px;
            border: none;
            border-radius: 5px;
            background-color: #007bff;
            color: #fff;
            cursor: pointer;
        }

        button:hover {
            background-color: #008aff;
        }

        .form-container {
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
    </style>
    <script>
        function updateCountryStatus(countryId, checked) {
            fetch('/update_country_status', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ id: countryId, picked: checked })
            })
            .then(response => response.json())
            .then(data => {
                console.log('Country status updated:', data);
            })
            .catch(error => console.error('Error:', error));
        }

        function addPortRow() {
            const table = document.getElementById('portTable');
            const row = table.insertRow();
            const cell1 = row.insertCell(0);
            const cell2 = row.insertCell(1);
            const cell3 = row.insertCell(2);
            const cell4 = row.insertCell(3);

            cell1.innerHTML = '<input type="text" name="port_number[]" placeholder="Port Number" required>';
            cell2.innerHTML = '<select name="protocol[]"><option value="tcp">TCP</option><option value="udp">UDP</option></select>';
            cell3.innerHTML = '<button type="button" onclick="deletePortRow(this)">Delete</button>';
        }

        function deletePortRow(btn) {
            const row = btn.parentNode.parentNode;
            row.parentNode.removeChild(row);
        }

        function addWhitelistRow() {
            const table = document.getElementById('whitelistTable');
            const row = table.insertRow();
            const cell1 = row.insertCell(0);
            const cell2 = row.insertCell(1);

            cell1.innerHTML = '<input type="text" name="whitelisted_ip[]" placeholder="IP in CIDR format" pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}($|/(16|24|32))$" required>';
            cell2.innerHTML = '<button type="button" onclick="deleteWhitelistRow(this)">Delete</button>';
        }

        function deleteWhitelistRow(btn) {
            const row = btn.parentNode.parentNode;
            row.parentNode.removeChild(row);
        }
    </script>
</head>
<body>
    <h1>Country GEOBLOCK. HOSTING SERVER</h1>
    <details>
        <summary style="font-size: 1.5em; font-weight: bold;">Countries list</summary>
        {% for country in countries %}
            <input type="checkbox" id="country_{{ country[0] }}" name="country_{{ country[0] }}" {% if (country[3] == 1) %}checked{% endif %} onchange="updateCountryStatus({{ country[0] }}, this.checked)"> {{ country[2] }} ({{ country[1] }})<br>
        {% endfor %}
    </details>
    
    <h2>Whitelist IPs</h2>
    <form action="/update-whitelist" method="post">
        <table id="whitelistTable">
            <tr>
                <th>IP Range(CIDR format)</th>
                <th>Action</th>
            </tr>
            {% for ip in whitelisted_ips %}
            <tr>
                <td>
                <input type="text" name="whitelisted_ip[]" value="{{ ip }}" 
                   pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}($|/(16|24|32))$" required>
                   </td>
                <td><button type="button" onclick="deleteWhitelistRow(this)">Delete</button></td>
            </tr>
            {% endfor %}
        </table>
        <button type="button" onclick="addWhitelistRow()">Add new Whitelist IP</button>
        <input type="submit" value="Save Whitelist">
    </form>


    <h2>Port Rules</h2>
    <form action="/update-ports" method="post">
        <table id="portTable">
            <tr>
                <th>Port Number</th>
                <th>Protocol</th>
                <th>Action</th>
            </tr>
            {% for rule in port_rules %}
            <tr>
                <td><input type="text" name="port_number[]" value="{{ rule[1] }}" required></td>
                <td>
                    <select name="protocol[]">
                        <option value="tcp" {% if rule[2] == 'tcp' %}selected{% endif %}>TCP</option>
                        <option value="udp" {% if rule[2] == 'udp' %}selected{% endif %}>UDP</option>
                    </select>
                </td>
                <td><button type="button" onclick="deletePortRow(this)">Delete</button></td>
            </tr>
            {% endfor %}
        </table>
        <button type="button" onclick="addPortRow()">Add new Rules</button>
        <input type="submit" value="Save Rules">
    </form>
    <br>


    <h2>System Actions</h2>
    <form action="/update_now" method="post">
        <input type="submit" value="Update Now">
    </form>
    <form action="/install_schedule" method="post">
        <input type="submit" value="Install Schedule">
    </form>
    <form action="/remove_schedule" method="post">
        <input type="submit" value="Remove Schedule">
    </form>

    <h2>System Info</h2>
    <p>{{ date_info }}</p>
    <p>{{ cron_info }}</p>
</body>
</html>

'''

#### DATABASE SECTION ####

def populate_countries():
    """Populate the countries table with sample data."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS countries (
                id INTEGER PRIMARY KEY,
                code TEXT UNIQUE,
                name TEXT,
                picked BOOLEAN
            )
        ''')
        countries = [
            (1, 'AE', 'United Arab Emirates', False),
            (2, 'AL', 'Albania', False),
            (3, 'AM', 'Armenia', False),
            (4, 'AR', 'Argentina', False),
            (5, 'AU', 'Australia', False),
            (6, 'AT', 'Austria', False),
            (7, 'AZ', 'Azerbaijan', False),
            (8, 'BA', 'Bosnia & Herzegovina', False),
            (9, 'BE', 'Belgium', False),
            (10, 'BG', 'Bulgaria', False),
            (11, 'BO', 'Bolivia', False),
            (12, 'BR', 'Brazil', False),
            (13, 'BW', 'Botswana', False),
            (14, 'BY', 'Belarus', False),
            (15, 'CA', 'Canada', False),
            (16, 'CG', 'Congo, Republic', False),
            (17, 'CH', 'Switzerland', False),
            (18, 'CN', 'China', False),
            (19, 'CO', 'Colombia', False),
            (20, 'CR', 'Costa Rica', False),
            (21, 'CY', 'Cyprus', False),
            (22, 'CZ', 'Czech Republic', False),
            (23, 'DE', 'Germany', False),
            (24, 'DK', 'Denmark', False),
            (25, 'EE', 'Estonia', False),
            (26, 'ES', 'Spain', False),
            (27, 'FI', 'Finland', False),
            (28, 'FR', 'France', False),
            (29, 'GB', 'United Kingdom', False),
            (30, 'GE', 'Georgia', False),
            (31, 'GH', 'Ghana', False),
            (32, 'GR', 'Greece', False),
            (33, 'HK', 'Hong Kong', False),
            (34, 'HR', 'Croatia', False),
            (35, 'HU', 'Hungary', False),
            (36, 'ID', 'Indonesia', False),
            (37, 'IE', 'Ireland', False),
            (38, 'IL', 'Israel', False),
            (39, 'IN', 'India', False),
            (40, 'IR', 'Iran', False),
            (41, 'IS', 'Iceland', False),
            (42, 'IT', 'Italy', False),
            (43, 'JP', 'Japan', False),
            (44, 'KE', 'Kenya', False),
            (45, 'KG', 'Kyrgyz Republic', False),
            (46, 'KR', 'Korea, Republic', False),
            (47, 'KZ', 'Kazakhstan', False),
            (48, 'LB', 'Lebanon', False),
            (49, 'LI', 'Liechtenstein', False),
            (50, 'LK', 'Sri Lanka', False),
            (51, 'LT', 'Lithuania', False),
            (52, 'LU', 'Luxembourg', False),
            (53, 'LV', 'Latvia', False),
            (54, 'MA', 'Morocco', False),
            (55, 'MC', 'Monaco', False),
            (56, 'MD', 'Moldova', False),
            (57, 'ME', 'Montenegro', False),
            (58, 'MK', 'Macedonia', False),
            (59, 'MM', 'Myanmar', False),
            (60, 'MQ', 'Martinique', False),
            (61, 'MT', 'Malta', False),
            (62, 'MX', 'Mexico', False),
            (63, 'MY', 'Malaysia', False),
            (64, 'NG', 'Nigeria', False),
            (65, 'NL', 'Netherlands', False),
            (66, 'NO', 'Norway', False),
            (67, 'NZ', 'New Zealand', False),
            (68, 'PE', 'Peru', False),
            (69, 'PH', 'Philippines', False),
            (70, 'PL', 'Poland', False),
            (71, 'PS', 'Palestine, State of', False),
            (72, 'PT', 'Portugal', False),
            (73, 'RO', 'Romania', False),
            (74, 'RS', 'Serbia', False),
            (75, 'RU', 'Russia', False),
            (76, 'SE', 'Sweden', False),
            (77, 'SG', 'Singapore', False),
            (78, 'SI', 'Slovenia', False),
            (79, 'SK', 'Slovakia', False),
            (80, 'SR', 'Suriname', False),
            (81, 'SV', 'El Salvador', False),
            (82, 'TR', 'Turkey', False),
            (83, 'UA', 'Ukraine', False),
            (84, 'UG', 'Uganda', False),
            (85, 'US', 'U.S.A.', False),
            (86, 'VE', 'Venezuela', False),
            (87, 'XK', 'Kosova', False),
            (88, 'XS', 'Srpska', False),
            (89, 'ZA', 'South Africa', False),
            (90, 'ZM', 'Zambia', False)
        ]
        cursor.executemany('INSERT OR IGNORE INTO countries (id, code, name, picked) VALUES (?, ?, ?, ?)', countries)
        conn.commit()

def init_db():
    """Initialize the SQLite database."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS countries (id INTEGER PRIMARY KEY, code TEXT, name TEXT, picked BOOLEAN)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS whitelisted_ips (id INTEGER PRIMARY KEY, cidr TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS port_rules (id INTEGER PRIMARY KEY, port_number INTEGER, protocol TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS system_info (last_update_date DATETIME)''')
        conn.commit()
    populate_countries()

def get_countries():
    """Fetch the list of countries and their statuses."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM countries')
        return cursor.fetchall()

def get_whitelisted_ips():
    """Fetch the list of whitelisted IPs."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT cidr FROM whitelisted_ips')
        return [row[0] for row in cursor.fetchall()]

def add_ip_to_whitelist(cidr):
    """Add CIDR to the database."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO whitelisted_ips (cidr) VALUES (?)', (cidr,))
        conn.commit()

def get_port_rules():
    """Fetch the list of port rules."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM port_rules')
        return cursor.fetchall()

@app.route('/save_whitelist', methods=['POST'])
def save_whitelist():
    whitelisted_ips = request.form.getlist('whitelisted_ip[]')

    for ip in whitelisted_ips:
        if not netaddr.valid_ipv4_cidr(ip):
            print(f"Invalid CIDR Format: {ip}")
            return f"Invalid CIDR format: {ip}", 400

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT cidr FROM whitelisted_ips WHERE cidr = ?', (ip,))
            result = cursor.fetchone()
            if result is None:
                cursor.execute('INSERT INTO whitelisted_ips (cidr) VALUES (?)', (ip,))
                conn.commit()

        iptables_check = run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'ACCEPT'], capture_output=True, text=True)
        if iptables_check.returncode != 0:
            run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'ACCEPT'])

    return redirect(url_for('index'))


#### FLASK SECTION ####

@app.route('/')
def index():
    countries = get_countries()
    whitelisted_ips = get_whitelisted_ips()
    port_rules = get_port_rules()

    cron_info = "Cron job info: " + ("Set" if cron_job_exists() else "Not set")
    date_info = "Last set date: "

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT last_update_date FROM system_info')
        result = cursor.fetchone()
        last_update_date = datetime.fromisoformat(result[0]).strftime("%B %d, %Y, %I:%M %p") if result else "NONE"
            
        date_info += str(last_update_date)
    
    return render_template_string(HTML_TEMPLATE, countries=countries, cron_info=cron_info, date_info=date_info, port_rules=port_rules, whitelisted_ips=whitelisted_ips)


@app.route('/update-whitelist', methods=['POST'])
def update_whitelist():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        cursor.execute('DELETE FROM whitelisted_ips')
        whitelisted_ips = request.form.getlist('whitelisted_ip[]')
        valid_ips = [ip for ip in whitelisted_ips if is_valid_cidr(ip)]

        for ip in valid_ips:
            cursor.execute('INSERT INTO whitelisted_ips (cidr) VALUES (?)', (ip,))
        print(f"Valid whitelisted IPs: {valid_ips}")

        conn.commit()

    return redirect(url_for('index'))


@app.route('/update-ports', methods=['POST'])
def update_ports():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        port_numbers = request.form.getlist('port_number[]')
        protocols = request.form.getlist('protocol[]')

        print(f"port numbers: {port_numbers}")
        print(f"protocols: {protocols}")
        cursor.execute('DELETE FROM port_rules')
        for port_number, protocol in zip(port_numbers, protocols):
            cursor.execute('INSERT INTO port_rules (port_number, protocol) VALUES (?, ?)', (port_number, protocol))

        conn.commit()

    return redirect(url_for('index'))


def run_update():
    global update_completed
    update_completed = False
    update()
    print("Updated! Setting update_completed as True!")
    update_completed = True

@app.route('/task_status', methods=['GET'])
def task_status():
    global update_completed
    return jsonify({'completed': update_completed})

@app.route('/update_now', methods=['POST'])
def update_now():
    thread = Thread(target=run_update)
    thread.start()
    return redirect(url_for('update_status'))

@app.route('/update_status')
def update_status():
    return render_template_string('''
        <html>
        <body>
            <h1>Update in progress...</h1>
            <p>The update process has started. Please wait.</p>
            <script>
                function checkStatus() {
                    console.log("Fetching task_status...")
                    fetch('/task_status')
                        .then(response => response.json())
                        .then(data => {
                            console.log("Data: ", data)
                            if (data.completed) {
                                setTimeout(() => window.location.href = "{{ url_for('index') }}", 2000);
                            } else {
                                setTimeout(checkStatus, 2000);
                            }
                        });
                }
                checkStatus();
            </script>
        </body>
        </html>
    ''')

@app.route('/install_schedule', methods=['POST'])
def install_schedule():
    try:
        crontab = check_output(['crontab', '-l']).decode('utf-8')
    except CalledProcessError:
        crontab = ''

    if CRON_JOB not in crontab:
        crontab += f'\n{CRON_JOB}\n'

        with Popen(['crontab', '-'], stdin=PIPE) as proc:
            proc.communicate(input=crontab.encode('utf-8'))

        reboot_job = f'@reboot /usr/bin/python3 /opt/hosting/geoblock/updater.py\n'
        with Popen(['crontab', '-'], stdin=PIPE) as proc:
            proc.communicate(input=(crontab + reboot_job).encode('utf-8'))
    return redirect(url_for('index'))

@app.route('/remove_schedule', methods=['POST'])
def remove_schedule():
    try:
        crontab = check_output(['crontab', '-l']).decode('utf-8')
    except CalledProcessError:
        crontab = ''

    lines = crontab.splitlines()
    lines = [line for line in lines if line.strip() != CRON_JOB]

    with Popen(['crontab', '-'], stdin=PIPE) as proc:
        proc.communicate(input='\n'.join(lines).encode('utf-8'))
    return redirect(url_for('index'))

@app.route('/update_country_status', methods=['POST'])
def update_country_status():
    data = request.get_json()
    country_id = data.get('id')
    picked = data.get('picked')
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE countries SET picked = ? WHERE id = ?', (picked, country_id))
        conn.commit()

    return {'status': 'success'}, 200

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)

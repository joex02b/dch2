import http.client
import json
import gzip
import io
from datetime import datetime, timezone
import secrets
import string
import hashlib
import subprocess
import time
import os
import ssl
from datetime import datetime

# Set expiration date (YYYY-MM-DD)
EXPIRATION_DATE = "2025-06-30"


def check_expiration():
    """Check if the program has expired."""
    current_date = datetime.now().strftime("%Y-%m-%d")
    if current_date > EXPIRATION_DATE:
        print(f"Infocean's Program expired on {EXPIRATION_DATE}. Exiting...")
        exit(1)


# Track processed logs to avoid duplicates
processed_logs = set()
check_expiration()


def display_filter_options():
    """Display available filter options for users"""
    print("\n" + "=" * 60)
    print("PALO ALTO XDR ALERT FILTER OPTIONS")
    print("=" * 60)

    print("\n📋 AVAILABLE FILTER FIELDS:")
    print("1. severity - List of strings representing the alert severities")
    print("2. creation_time - Timestamp of when the alert was originally identified")
    print("3. server_creation_time - Timestamp of when the alert was stored in the database")
    print("4. alert_id_list - List of integers representing the alert IDs")
    print("5. alert_source - List of strings representing the alert sources")

    print("\n🔍 AVAILABLE OPERATORS:")
    print("- in: Value is in the list (alert_id_list, alert_source, and severity)")
    print("- gte: Greater than or equal to (creation_time and server_creation_time)")
    print("- lte: Less than or equal to (creation_time and server_creation_time)")

    print("\n SEVERITY VALUES:")
    print("- low, medium, high, critical")

    print("\n Time:")
    print("- UTC timezone")

    print("\n alert_id_list: Array of integers. Each item in the list must be an alert ID")

def get_custom_filters():
    """Interactive function to build custom filters"""
    filters = []

    print("\n🔧 CUSTOM FILTER BUILDER")
    print("Enter 'done' when finished adding filters")
    print("Enter 'help' to see filter options again")

    while True:
        print(f"\n📝 Current filters: {len(filters)}")
        if filters:
            for i, f in enumerate(filters, 1):
                print(f"   {i}. {f['field']} {f['operator']} {f['value']}")

        choice = input("\nAction (add/remove/done/help): ").strip().lower()

        if choice == 'done':
            break
        elif choice == 'help':
            display_filter_options()
            continue
        elif choice == 'remove' and filters:
            try:
                idx = int(input("Enter filter number to remove: ")) - 1
                if 0 <= idx < len(filters):
                    removed = filters.pop(idx)
                    print(f"✅ Removed filter: {removed}")
                else:
                    print("❌ Invalid filter number")
            except ValueError:
                print("❌ Please enter a valid number")
            continue
        elif choice != 'add':
            print("❌ Invalid choice. Use: add, remove, done, or help")
            continue

        # Add new filter
        print("\n➕ Adding new filter:")
        field = input("Field name: ").strip()
        if not field:
            print("❌ Field name cannot be empty")
            continue

        operator = input("Operator (in/gte/lte/contains/eq): ").strip()
        if operator not in ['in', 'gte', 'lte', 'contains', 'eq']:
            print("❌ Invalid operator")
            continue

        print("Value(s) - for 'in' operator, separate multiple values with commas:")
        value_input = input("Value: ").strip()

        if operator == 'in':
            # Split by comma and clean up
            value = [v.strip() for v in value_input.split(',') if v.strip()]
            if not value:
                print("❌ At least one value required for 'in' operator")
                continue
        else:
            value = value_input
            if not value:
                print("❌ Value cannot be empty")
                continue

        new_filter = {
            "field": field,
            "operator": operator,
            "value": value
        }

        filters.append(new_filter)
        print(f"✅ Added filter: {new_filter}")

    return filters


def get_search_parameters():
    """Get search parameters from user"""
    print("\n🔍 SEARCH PARAMETERS")

    try:
        search_from = int(input("Search from (default 0): ") or "0")
        search_to = int(input("Search to (default 100, max 1000): ") or "100")

        if search_to > 1000:
            print("⚠️  Maximum search_to is 1000, setting to 1000")
            search_to = 1000

        return search_from, search_to
    except ValueError:
        print("❌ Invalid input, using defaults (0, 100)")
        return 0, 100


def create_custom_payload():
    """Create custom payload based on user input"""
    print("\n" + "=" * 60)
    print("CUSTOM PAYLOAD BUILDER")
    print("=" * 60)

    choice = input("\nUse custom filters? (y/n, default=n): ").strip().lower()

    if choice == 'y':
        display_filter_options()
        filters = get_custom_filters()
    else:
        # Default filter for low severity
        filters = [{"field": "severity", "operator": "in", "value": ["low"]}]
        print("Using default filter: severity = low")

    search_from, search_to = get_search_parameters()

    payload = {
        "request_data": {
            "filters": filters,
            "search_from": search_from,
            "search_to": search_to,
        }
    }

    print("\n📦 GENERATED PAYLOAD:")
    print(json.dumps(payload, indent=2))

    confirm = input("\nUse this payload? (y/n): ").strip().lower()
    if confirm != 'y':
        print("❌ Payload creation cancelled")
        return None

    return payload


def save_payload_template(payload, filename="payload_template.json"):
    """Save payload as template for future use"""
    try:
        with open(filename, 'w') as f:
            json.dump(payload, f, indent=2)
        print(f"✅ Payload template saved to {filename}")
    except Exception as e:
        print(f"❌ Failed to save template: {e}")


def load_payload_template(filename="payload_template.json"):
    """Load payload from template file"""
    try:
        with open(filename, 'r') as f:
            payload = json.load(f)
        print(f"✅ Payload template loaded from {filename}")
        print("Loaded payload:")
        print(json.dumps(payload, indent=2))
        return payload
    except FileNotFoundError:
        print(f"❌ Template file {filename} not found")
        return None
    except Exception as e:
        print(f"❌ Failed to load template: {e}")
        return None


def generate_auth_headers(api_key_id, api_key):
    """Generate the proper authentication headers"""
    nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
    timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)
    auth_key = f"{api_key}{nonce}{timestamp}".encode("utf-8")
    api_key_hash = hashlib.sha256(auth_key).hexdigest()

    return {
        "x-xdr-timestamp": str(timestamp),
        "x-xdr-nonce": nonce,
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key_hash,
        "Accept-Encoding": "gzip",
        "Content-Type": "application/json"
    }


def forward_to_syslog(message, syslog_server: str):
    """Forward message to syslog server using curl"""
    try:
        syslog_msg = f"<14>{datetime.now().strftime('%b %d %H:%M:%S')} {message}"
        cmd = [
            'curl',
            '-s',
            '-X', 'POST',
            '--data-binary', syslog_msg,
            f'{syslog_server}:514'
        ]
        subprocess.run(cmd, check=True)
        print("Message forwarded to syslog server")
    except subprocess.CalledProcessError as e:
        print(f"Failed to forward to syslog: {str(e)}")


def check_and_forward(response_data, syslog_server):
    """Check response for specific string and forward if found"""
    response_str = json.dumps(response_data)
    forward_to_syslog(response_str, syslog_server)


def write_to_log_file(data, log_file: str):
    """Write data to log file with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not isinstance(data, str):
        data = json.dumps(data, indent=2)

    log_entry = f"{data}\n"
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    with open(log_file, "a") as f:
        f.write(log_entry)

    print(f"Data written to {log_file}")


def is_duplicate_log(log_data):
    """Check if the log is a duplicate"""
    log_hash = hashlib.sha256(json.dumps(log_data).encode('utf-8')).hexdigest()
    if log_hash in processed_logs:
        return True
    processed_logs.add(log_hash)
    return False


def poll_incidents_real_time(interval: int, log_file: str, syslog_server: str, payload):
    """Poll for incidents at regular intervals and save to log file"""
    print(f"Starting real-time log polling (every {interval} seconds)")

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        while True:
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Polling for incidents...")

            try:
                conn = http.client.HTTPSConnection(HOST, context=ssl_context)
                headers = generate_auth_headers(API_KEY_ID, API_KEY)

                conn.request("POST", ENDPOINT, body=json.dumps(payload), headers=headers)
                res = conn.getresponse()

                data = res.read()
                if res.getheader('Content-Encoding') == 'gzip':
                    with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
                        response = json.loads(f.read().decode('utf-8'))
                else:
                    response = json.loads(data.decode('utf-8'))

                print("Response status:", res.status)

                if is_duplicate_log(response):
                    print("Duplicate log detected. Skipping...")
                else:
                    write_to_log_file(response, log_file)
                    check_and_forward(response, syslog_server)

            except Exception as e:
                error_msg = f"Error during API call: {str(e)}"
                print(error_msg)
                write_to_log_file(error_msg, log_file)
            finally:
                conn.close()

            print(f"Waiting {interval} seconds before next poll...")
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nPolling stopped by user")


# Configuration
API_KEY_ID = input("API_KEY_ID(default: 17): ") or "17"
API_KEY = input("API_KEY(default: vDjHX....): ") or "vDjHXearPR1zRM5wq90jy6WIeZ0RoFftp2YlgXfONrdlD7PiNT6n4wQ9OPjJXB5hEMtkHywSOjmDJoyZB5jj5MZTOmgpTWdY6D94sojqWVFGdgk7bUasnbHWrPVyTpLO"
HOST = "api-dch.xdr.sg.paloaltonetworks.com"
ENDPOINT = "/public_api/v1/alerts/get_alerts"
SYSLOG_SERVER = "127.0.0.1"
LOG_FILE = "./pa.json"
POLLING_INTERVAL = 0.1

if __name__ == "__main__":
    print("🚀 PALO ALTO XDR INCIDENT MONITORING")
    print("=" * 50)
    print(f"📁 Log file: {LOG_FILE}")
    print(f"📡 Syslog server: {SYSLOG_SERVER}:514")

    # Payload configuration options
    print("\n⚙️  PAYLOAD CONFIGURATION OPTIONS:")
    print("1. Create custom payload")
    print("2. Load from template file")
    print("3. Use default payload (severity=low)")

    choice = input("\nSelect option (1-3, default=3): ").strip()

    payload = None

    if choice == "1":
        payload = create_custom_payload()
        if payload:
            save_choice = input("Save this payload as template? (y/n): ").strip().lower()
            if save_choice == 'y':
                save_payload_template(payload)
    elif choice == "2":
        payload = load_payload_template()

    # Use default if no payload created/loaded
    if not payload:
        payload = {
            "request_data": {
                "filters": [
                    {"field": "severity", "operator": "in", "value": ["low"]}
                ],
                "search_from": 0,
                "search_to": 1,
            }
        }
        print("Using default payload (severity=low)")

    print("\n🔄 FINAL PAYLOAD:")
    print(json.dumps(payload, indent=2))

    input("\nPress Enter to start monitoring...")
    poll_incidents_real_time(POLLING_INTERVAL, LOG_FILE, SYSLOG_SERVER, payload)

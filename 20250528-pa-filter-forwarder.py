import http.client
import json
import gzip
import io
from datetime import datetime, timezone
import secrets
import string
import hashlib
import time
import os
import ssl
import socket
from datetime import datetime

# Set expiration date (YYYY-MM-DD)
EXPIRATION_DATE = "2025-06-30"


def check_expiration():
    """Check if the program has expired."""
    current_date = datetime.now().strftime("%Y-%m-%d")
    if current_date > EXPIRATION_DATE:
        print(f"Infocean's Program expired on {EXPIRATION_DATE}. Exiting...")
        exit(1)


# Track processed alert IDs to avoid duplicates
processed_alert_ids = set()
check_expiration()


def display_filter_options():
    """Display available filter options for users"""
    print("\n" + "=" * 60)
    print("PALO ALTO XDR ALERT FILTER OPTIONS")
    print("=" * 60)

    print("\n🗂️ AVAILABLE FILTER FIELDS:")
    print("1. severity - List of strings representing the alert severities")
    print("2. creation_time - Timestamp of when the alert was originally identified")
    print("3. server_creation_time - Timestamp of when the alert was stored in the database")
    print("4. alert_id_list - List of integers representing the alert IDs")
    print("5. alert_source - List of strings representing the alert sources")

    print("\n🔍 AVAILABLE OPERATORS:")
    print("- in: Value is in the list (alert_id_list, alert_source, and severity)")
    print("- gte: Greater than or equal to (creation_time and server_creation_time)")
    print("- lte: Less than or equal to (creation_time and server_creation_time)")

    print("\n⚠️ SEVERITY VALUES:")
    print("- low, medium, high, critical")

    print("\n⏰ Time:")
    print("- UTC timezone")

    print("\n🆔 alert_id_list: Array of integers. Each item in the list must be an alert ID")


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


def forward_to_syslog_udp(message, syslog_server: str, syslog_port: int = 514):
    """Forward message to syslog server using UDP"""
    try:
        # Create syslog message with proper RFC3164 format
        # Priority: <14> = facility 1 (user), severity 6 (info)
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        hostname = socket.gethostname()

        # Format the message as JSON if it's not already a string
        if not isinstance(message, str):
            message = json.dumps(message)

        # Create RFC3164 compliant syslog message
        syslog_msg = f"<14>{timestamp} {hostname} PaloAltoXDR: {message}"

        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)  # 5 second timeout

        # Send message
        sock.sendto(syslog_msg.encode('utf-8'), (syslog_server, syslog_port))
        sock.close()

        print(f"✅ Message forwarded to syslog server {syslog_server}:{syslog_port}")
        print(f"📏 Message size: {len(syslog_msg)} bytes")

    except socket.gaierror as e:
        print(f"❌ DNS resolution failed for {syslog_server}: {str(e)}")
    except socket.timeout:
        print(f"❌ Timeout sending to syslog server {syslog_server}:{syslog_port}")
    except Exception as e:
        print(f"❌ Failed to forward to syslog: {str(e)}")


def forward_to_syslog_udp_chunked(message, syslog_server: str, syslog_port: int = 514, max_chunk_size: int = 1024):
    """Forward large messages to syslog server using UDP with chunking"""
    try:
        # Format the message as JSON if it's not already a string
        if not isinstance(message, str):
            message = json.dumps(message)

        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        hostname = socket.gethostname()

        # Calculate available space for message content
        header_template = f"<14>{timestamp} {hostname} PaloAltoXDR[CHUNK_INFO]: "
        header_size = len(header_template.encode('utf-8'))
        available_size = max_chunk_size - header_size - 50  # Reserve 50 bytes for chunk info

        # Split message into chunks if needed
        if len(message.encode('utf-8')) <= available_size:
            # Single message
            syslog_msg = f"<14>{timestamp} {hostname} PaloAltoXDR: {message}"
            chunks = [syslog_msg]
        else:
            # Multiple chunks
            message_bytes = message.encode('utf-8')
            chunks = []
            total_chunks = (len(message_bytes) + available_size - 1) // available_size

            for i in range(total_chunks):
                start = i * available_size
                end = min(start + available_size, len(message_bytes))
                chunk_data = message_bytes[start:end].decode('utf-8', errors='ignore')

                chunk_info = f"[{i + 1}/{total_chunks}]"
                syslog_msg = f"<14>{timestamp} {hostname} PaloAltoXDR{chunk_info}: {chunk_data}"
                chunks.append(syslog_msg)

        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)  # 5 second timeout

        # Send all chunks
        for i, chunk in enumerate(chunks):
            sock.sendto(chunk.encode('utf-8'), (syslog_server, syslog_port))
            if len(chunks) > 1:
                time.sleep(0.01)  # Small delay between chunks

        sock.close()

        if len(chunks) > 1:
            print(f"✅ Message forwarded in {len(chunks)} chunks to {syslog_server}:{syslog_port}")
        else:
            print(f"✅ Message forwarded to syslog server {syslog_server}:{syslog_port}")
        print(f"📏 Total message size: {len(message.encode('utf-8'))} bytes")

    except socket.gaierror as e:
        print(f"❌ DNS resolution failed for {syslog_server}: {str(e)}")
    except socket.timeout:
        print(f"❌ Timeout sending to syslog server {syslog_server}:{syslog_port}")
    except Exception as e:
        print(f"❌ Failed to forward to syslog: {str(e)}")


def check_and_forward(response_data, syslog_server, syslog_port=514, use_chunking=True):
    """Check response and forward to syslog server"""
    if use_chunking:
        forward_to_syslog_udp_chunked(response_data, syslog_server, syslog_port)
    else:
        forward_to_syslog_udp(response_data, syslog_server, syslog_port)


def write_to_log_file(data, log_file: str):
    """Write data to log file with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not isinstance(data, str):
        data = json.dumps(data, indent=2)

    log_entry = f"{data}\n"
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    with open(log_file, "a") as f:
        f.write(log_entry)

    print(f"📁 Data written to {log_file}")


def extract_alert_ids(response_data):
    """Extract alert IDs from the API response"""
    alert_ids = set()

    try:
        # Navigate through the response structure to find alerts
        if isinstance(response_data, dict):
            # Check for alerts in reply
            if 'reply' in response_data and isinstance(response_data['reply'], dict):
                alerts = response_data['reply'].get('alerts', [])
            # Check for alerts at root level
            elif 'alerts' in response_data:
                alerts = response_data['alerts']
            else:
                alerts = []

            # Extract alert IDs
            for alert in alerts:
                if isinstance(alert, dict) and 'alert_id' in alert:
                    alert_ids.add(str(alert['alert_id']))

    except Exception as e:
        print(f"❌ Error extracting alert IDs: {e}")

    return alert_ids


def is_duplicate_alert(response_data):
    """Check if any alerts in the response are duplicates based on alert_id"""
    current_alert_ids = extract_alert_ids(response_data)

    if not current_alert_ids:
        # If no alert IDs found, treat as unique (might be error response or empty result)
        return False

    # Check if any alert ID is already processed
    duplicates = current_alert_ids.intersection(processed_alert_ids)

    if duplicates:
        print(f"🔄 Found duplicate alert IDs: {duplicates}")
        return True

    # Add new alert IDs to processed set
    processed_alert_ids.update(current_alert_ids)
    print(f"🆕 Added new alert IDs: {current_alert_ids}")

    return False


def filter_new_alerts(response_data):
    """Filter out duplicate alerts and return only new ones"""
    if not isinstance(response_data, dict):
        return response_data

    try:
        # Create a copy of the response
        filtered_response = response_data.copy()

        # Navigate to alerts
        if 'reply' in response_data and isinstance(response_data['reply'], dict):
            alerts = response_data['reply'].get('alerts', [])
            filtered_alerts = []

            for alert in alerts:
                if isinstance(alert, dict) and 'alert_id' in alert:
                    alert_id = str(alert['alert_id'])
                    if alert_id not in processed_alert_ids:
                        filtered_alerts.append(alert)
                        processed_alert_ids.add(alert_id)
                        print(f"🆕 New alert ID: {alert_id}")
                    else:
                        print(f"⏭️  Skipping duplicate alert ID: {alert_id}")
                else:
                    # Include alerts without IDs (shouldn't happen but just in case)
                    filtered_alerts.append(alert)

            # Update the response with filtered alerts
            filtered_response['reply']['alerts'] = filtered_alerts

        elif 'alerts' in response_data:
            alerts = response_data['alerts']
            filtered_alerts = []

            for alert in alerts:
                if isinstance(alert, dict) and 'alert_id' in alert:
                    alert_id = str(alert['alert_id'])
                    if alert_id not in processed_alert_ids:
                        filtered_alerts.append(alert)
                        processed_alert_ids.add(alert_id)
                        print(f"🆕 New alert ID: {alert_id}")
                    else:
                        print(f"⏭️  Skipping duplicate alert ID: {alert_id}")
                else:
                    filtered_alerts.append(alert)

            filtered_response['alerts'] = filtered_alerts

        return filtered_response

    except Exception as e:
        print(f"❌ Error filtering alerts: {e}")
        return response_data


def test_syslog_connection(syslog_server: str, syslog_port: int = 514):
    """Test UDP connection to syslog server"""
    try:
        print(f"\n🧪 Testing syslog connection to {syslog_server}:{syslog_port}")

        test_message = f"<14>{datetime.now().strftime('%b %d %H:%M:%S')} {socket.gethostname()} PaloAltoXDR: Test connection from Palo Alto XDR monitor"

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        sock.sendto(test_message.encode('utf-8'), (syslog_server, syslog_port))
        sock.close()

        print(f"✅ Syslog test message sent successfully to {syslog_server}:{syslog_port}")
        return True

    except socket.gaierror as e:
        print(f"❌ DNS resolution failed for {syslog_server}: {str(e)}")
        return False
    except socket.timeout:
        print(f"❌ Timeout connecting to syslog server {syslog_server}:{syslog_port}")
        return False
    except Exception as e:
        print(f"❌ Failed to test syslog connection: {str(e)}")
        return False


def poll_incidents_real_time(interval: int, log_file: str, syslog_server: str, syslog_port: int, payload,
                             use_chunking: bool = True, filter_mode: str = "skip"):
    """Poll for incidents at regular intervals and save to log file"""
    print(f"🚀 Starting real-time log polling (every {interval} seconds)")
    print(f"🔄 Duplicate detection: Alert ID-based")
    print(f"📡 Syslog server: {syslog_server}:{syslog_port}")
    print(f"📦 Chunking enabled: {use_chunking}")
    print(f"🎯 Filter mode: {filter_mode}")

    # Test syslog connection first
    if not test_syslog_connection(syslog_server, syslog_port):
        print("⚠️  Syslog connection test failed, but continuing anyway...")

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        while True:
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 🔍 Polling for incidents...")

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

                print(f"📊 Response status: {res.status}")

                # Extract alert IDs for logging
                alert_ids = extract_alert_ids(response)
                if alert_ids:
                    print(f"🆔 Response contains alert IDs: {alert_ids}")
                else:
                    print("🔍 No alert IDs found in response")

                # Process based on filter mode
                if filter_mode == "skip":
                    # Skip entire response if any alerts are duplicates
                    if is_duplicate_alert(response):
                        print("⏭️  Duplicate alerts detected. Skipping entire response...")
                    else:
                        write_to_log_file(response, log_file)
                        check_and_forward(response, syslog_server, syslog_port, use_chunking)

                elif filter_mode == "filter":
                    # Filter out duplicate alerts and process only new ones
                    filtered_response = filter_new_alerts(response)

                    # Check if there are any alerts left after filtering
                    has_alerts = False
                    if 'reply' in filtered_response and filtered_response['reply'].get('alerts'):
                        has_alerts = len(filtered_response['reply']['alerts']) > 0
                    elif 'alerts' in filtered_response and filtered_response['alerts']:
                        has_alerts = len(filtered_response['alerts']) > 0

                    if has_alerts:
                        write_to_log_file(filtered_response, log_file)
                        check_and_forward(filtered_response, syslog_server, syslog_port, use_chunking)
                    else:
                        print("🚫 No new alerts to process after filtering")

            except Exception as e:
                error_msg = f"Error during API call: {str(e)}"
                print(f"❌ {error_msg}")
                write_to_log_file(error_msg, log_file)
            finally:
                conn.close()

            print(f"📈 Processed alert IDs so far: {len(processed_alert_ids)}")
            print(f"⏰ Waiting {interval} seconds before next poll...")
            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n⏹️  Polling stopped by user")
        print(f"📊 Total unique alerts processed: {len(processed_alert_ids)}")


# Configuration
API_KEY_ID = input("API_KEY_ID(default: 17): ") or "17"
API_KEY = input(
    "API_KEY(default: vDjHX....): ") or "vDjHXearPR1zRM5wq90jy6WIeZ0RoFftp2YlgXfONrdlD7PiNT6n4wQ9OPjJXB5hEMtkHywSOjmDJoyZB5jj5MZTOmgpTWdY6D94sojqWVFGdgk7bUasnbHWrPVyTpLO"
HOST = "api-dch.xdr.sg.paloaltonetworks.com"
ENDPOINT = "/public_api/v1/alerts/get_alerts"

# Syslog configuration
SYSLOG_SERVER = input("Syslog Server IP/Hostname (default: 10.76.33.77): ") or "10.76.33.77"
try:
    SYSLOG_PORT = int(input("Syslog Port (default: 514): ") or "514")
except ValueError:
    SYSLOG_PORT = 514
    print("Invalid port, using default 514")

LOG_FILE = "./pa.json"
POLLING_INTERVAL = 0.1

# Chunking option
chunking_choice = input("Enable message chunking for large payloads? (y/n, default=y): ").strip().lower()
USE_CHUNKING = chunking_choice != 'n'

# Duplicate handling mode
print("\n🎯 DUPLICATE HANDLING OPTIONS:")
print("1. skip - Skip entire response if any duplicates found")
print("2. filter - Filter out duplicate alerts, process only new ones")
filter_choice = input("Select mode (1-2, default=1): ").strip()
FILTER_MODE = "filter" if filter_choice == "2" else "skip"

if __name__ == "__main__":
    print("🚀 PALO ALTO XDR INCIDENT MONITORING")
    print("=" * 50)
    print(f"📁 Log file: {LOG_FILE}")
    print(f"📡 Syslog server: {SYSLOG_SERVER}:{SYSLOG_PORT}")
    print(f"📦 Message chunking: {'Enabled' if USE_CHUNKING else 'Disabled'}")
    print(f"🎯 Duplicate handling: {FILTER_MODE}")

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
    poll_incidents_real_time(POLLING_INTERVAL, LOG_FILE, SYSLOG_SERVER, SYSLOG_PORT, payload, USE_CHUNKING, FILTER_MODE)

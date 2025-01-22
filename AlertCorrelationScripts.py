import sys
import json
import requests
import time
import os
from datetime import datetime, timedelta, timezone
from socket import socket, AF_UNIX, SOCK_DGRAM

# Define the logging function
def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
    print(msg)
    with open(log_file, "a") as f:
        f.write(str(msg))

# Define the function to send event
def send_event(msg, agent=None):
    if not agent or agent["id"] == "000":
        string = '1:custom:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->custom:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))

    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

# Get the current time
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Initialize last processed alert IDs
last_snort_alert_id = None
last_suricata_alert_id = None
last_zeek_alert_id = None

def main(args):
    global last_snort_alert_id, last_suricata_alert_id, last_zeek_alert_id
    debug("# Starting")
    # Read args
    alert_file_location = args[1]
    hook_url = args[2]
    debug("# Hook URL")
    debug(hook_url)
    debug("# File location")
    debug(alert_file_location)

    # Load alerts from file
    with open(alert_file_location) as alert_file:
        lines = alert_file.readlines()  # Read all lines into memory once

    # Get the current time minus 2 minutes
    time_threshold = datetime.now(timezone.utc) - timedelta(minutes=2)

    # Initialize lists to store alerts by IDS system
    snort_alerts = []
    suricata_alerts = []
    zeek_alerts = []

    for line in lines:
        line = line.strip()  # Remove leading/trailing whitespace, including newlines

        if not line:  # Skip empty lines
            continue

        try:
            json_alert = json.loads(line)
        except json.JSONDecodeError as e:
            debug(f"# JSONDecodeError: {e} on line: {line}")
            continue  # Skip this line and move to the next one

        alert_timestamp = datetime.strptime(json_alert["timestamp"], '%Y-%m-%dT%H:%M:%S.%f%z')

        if alert_timestamp < time_threshold:
            continue  # Skip lines older than 2 minutes

        # Extract issue fields
        alert_id = json_alert['id']  # Extract the alert ID
        alert_level = json_alert['rule']['level']
        ruleid = json_alert['rule']['id']
        description = json_alert['rule']['description']
        agentid = json_alert['agent']['id']
        agentname = json_alert['agent']['name']

        # Categorize the alerts based on the agent name and rule ID
        if agentname == "Agent01_Snort" and ruleid == "20101":
            if "Possible DDoS" in json_alert["full_log"]:
                snort_alerts.append({
                    'timestamp': json_alert["timestamp"],
                    'alert_level': alert_level,
                    'ruleid': ruleid,
                    'description': description,
                    'agentid': agentid,
                    'agentname': agentname,
                    'full_log': json_alert["full_log"],
                    'message': "DDoS detected from Snort IDS",
                    'alert_id': alert_id
                })

        elif agentname == "Agent02_Suricata" and ruleid == "86601":
            if "DDoS" in json_alert["data"]["alert"]["signature"]:
                suricata_alerts.append({
                    'timestamp': json_alert["timestamp"],
                    'alert_level': alert_level,
                    'ruleid': ruleid,
                    'description': description,
                    'agentid': agentid,
                    'agentname': agentname,
                    'signature': json_alert["data"]["alert"]["signature"],
                    'message': "DDoS detected from Suricata IDS",
                    'alert_id': alert_id
                })

        elif agentname == "Agent03_Zeek" and ruleid == "66009":
            if "Possible DDoS" in json_alert["data"]["msg"]:
                zeek_alerts.append({
                    'timestamp': json_alert["timestamp"],
                    'alert_level': alert_level,
                    'ruleid': ruleid,
                    'description': description,
                    'agentid': agentid,
                    'agentname': agentname,
                    'message': "DDoS detected from Zeek IDS",
                    'msg': json_alert["data"]["msg"],
                    'alert_id': alert_id
                })

    # Generate alert_data by correlating matching alerts
    for i in range(min(len(snort_alerts), len(suricata_alerts), len(zeek_alerts))):
        time_threshold_alert = datetime.now(timezone.utc) - timedelta(seconds=65)
        snort_timestamp = datetime.strptime(snort_alerts[i]['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')
        suricata_timestamp = datetime.strptime(suricata_alerts[i]['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')
        zeek_timestamp = datetime.strptime(zeek_alerts[i]['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')

        # Check if current alert IDs are different from previous ones
        if (
            (last_snort_alert_id is None or last_snort_alert_id != snort_alerts[i]['alert_id']) and
            (last_suricata_alert_id is None or last_suricata_alert_id != suricata_alerts[i]['alert_id']) and
            (last_zeek_alert_id is None or last_zeek_alert_id != zeek_alerts[i]['alert_id'])
        ):
            # Update last processed alert IDs
            last_snort_alert_id = snort_alerts[i]['alert_id']
            last_suricata_alert_id = suricata_alerts[i]['alert_id']
            last_zeek_alert_id = zeek_alerts[i]['alert_id']

            # Only send if all timestamps are recent enough
            if snort_timestamp > time_threshold_alert and suricata_timestamp > time_threshold_alert and zeek_timestamp > time_threshold_alert:
                alert_data = {
                    'alert_correlation_description': "DDoS attack detected by all IDS systems",
                    'Suricata_timestamp': suricata_alerts[i]['timestamp'],
                    'zeek_timestamp': zeek_alerts[i]['timestamp'],
                    'snort_timestamp': snort_alerts[i]['timestamp'],
                    'snort_log': snort_alerts[i]['full_log'],
                    'suricata_signature': suricata_alerts[i]['signature'],
                    'zeek_msg': zeek_alerts[i]['msg'],
                    'snort_message': snort_alerts[i]['message'],
                    'suricata_message': suricata_alerts[i]['message'],
                    'zeek_message': zeek_alerts[i]['message'],
                }
                debug("# Alert data generated")
                debug(alert_data)
                send_event(alert_data)

if __name__ == "__main__":
    while True:
        try:
            # Read arguments
            bad_arguments = False
            if len(sys.argv) >= 3:
                debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
            else:
                debug("# Exiting: Bad arguments.")
                sys.exit(1)

            # Logging the call
            debug(f"{datetime.now().isoformat()} {' '.join(sys.argv)}")

            # Main function
            main(sys.argv)

            time.sleep(60)

        except Exception as e:
            debug(str(e))
            raise

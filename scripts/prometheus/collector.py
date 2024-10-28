import time
import subprocess
import json
from prometheus_client import start_http_server, Gauge

# Define the metrics
log_line_count = Gauge('syslog_line_count', 'Number of lines in /var/log/syslog')
archway_balance_metric = Gauge('archway_balance', 'Balance in Archway Relay Wallet')
icon_balance_metric = Gauge('icon_balance', 'Balance in Icon Relay Wallet')
service_status = Gauge('relayer_node_status', 'Relayer node status (active or inactive)', ['service_name'])
icon_chain_metric = Gauge('icon_block_height', 'Extracted values from the log', ['chain_name', 'chain_id'])
archway_chain_metric = Gauge('archway_block_height', 'Extracted values from the log', ['chain_name', 'chain_id'])
command_archway = "rly q balance archway default | grep -oP 'balance \{\K[^}]+' | sed 's/aconst//'"
command_icon = "rly q balance icon relayer_wallet | grep -oP 'balance \{\K[^}]+' | sed 's/ICX//'"
command_icon_height="grep 'icon' /home/ubuntu/.relayer/relay.log | tail -n 1 | grep -o '{.*}' | sed 's/latest_height/height/g'"

command_archway_height="grep 'archway' /home/ubuntu/.relayer/relay.log | tail -n 1 | grep -o '{.*}' | sed 's/latest_height/height/g'"

# Define a function to fetch and set the metric values
def fetch_metrics():
    try:
        # Run the 'wc -l' command on the syslog file and parse the result
        output = subprocess.check_output(['wc', '-l', '/var/log/syslog'])
        line_count = int(output.split()[0])  # Extract the line count
        log_line_count.set(line_count)
        archway_balance_output = subprocess.check_output(command_archway, shell=True, text=True)
        # print(archway_balance_output)
        archway_balance_value = archway_balance_output.strip()
        archway_balance_metric.set(archway_balance_value)  # Assuming balance is a numeric value
        icon_balance_output = subprocess.check_output(command_icon, shell=True, text=True)
        # print(icon_balance_output)
        icon_balance_value = icon_balance_output.strip()
        icon_balance_metric.set(icon_balance_value)  # Assuming balance is a numeric value
        # Check relayer node status
        status = subprocess.getoutput(f'systemctl is-active ibc-relayer.service')
        service_status.labels(service_name='ibc-relayer.service').set(1 if status == 'active' else 0)
        # Get block height - icon
        icon_output = subprocess.check_output(command_icon_height, shell=True, text=True, executable='/bin/bash')
        # print(icon_output)
        json_data = json.loads(icon_output)
        chain_name = json_data['chain_name']
        chain_id = json_data['chain_id']
        height = json_data['height']
        # print(f'{chain_id},{chain_name},{height}')
        icon_chain_metric.labels(chain_name=chain_name, chain_id=chain_id).set(height)
        # Get block height - archway
        archway_output = subprocess.check_output(command_archway_height, shell=True, text=True, executable='/bin/bash')
        # print(archway_output)
        json_data = json.loads(archway_output)
        if 'error' in json_data:
            error_message = json_data['error']
            # Handle the error message, for example, by logging it or raising an exception.
            print(f"Error: {error_message}")
            # chain_name = json_data['chain_name']
            # chain_id = json_data['chain_id']
            # archway_chain_metric.labels(chain_name=chain_name, chain_id=chain_id).set(2434508)

        else:
            chain_name = json_data['chain_name']
            chain_id = json_data['chain_id']
            height = json_data['height']
            # print(f'{chain_id},{chain_name},{height}')
            archway_chain_metric.labels(chain_name=chain_name, chain_id=chain_id).set(height)
    except Exception as e:
        print(f"Failed to fetch metrics: {e}")

if __name__ == '__main__':
    # Start an HTTP server for Prometheus to scrape the metrics
    start_http_server(8000)

    # Run the commands and update the metric values every 5 seconds
    while True:
        fetch_metrics()
        time.sleep(5)

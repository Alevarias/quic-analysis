import pandas as pd
import json
from collections import defaultdict
import ipaddress
import os

# LinkedIn IP Ranges (Common, not exhaustive)
linkedin_ipv4_ranges = [
    '108.174.0.0/23', '108.174.8.0/24', '108.174.10.0/24', '108.174.13.0/24',
    '108.174.14.0/23', '144.2.9.0/24', '144.2.12.0/22', '144.2.16.0/24',
    '199.101.160.0/22', '216.52.16.0/24'
]

linkedin_ipv6_ranges = ['2620:109:c000::/47', '2620:109:c002::/48']

# Convert ranges to networks
linkedin_ipv4_networks = [ipaddress.ip_network(ip) for ip in linkedin_ipv4_ranges]
linkedin_ipv6_networks = [ipaddress.ip_network(ip) for ip in linkedin_ipv6_ranges]


def is_linkedin_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            for network in linkedin_ipv4_networks:
                if ip_obj in network:
                    return True
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            for network in linkedin_ipv6_networks:
                if ip_obj in network:
                    return True
    except ValueError:
        pass
    return False


def verify_and_load_csv(input_csv):
    expected_columns = ["time_relative", "frame_len", "ip_src", "ip_dst"]

    with open(input_csv, 'r') as file:
        first_line = file.readline()

    if not all(col in first_line for col in expected_columns):
        print("Warning: CSV headers are incorrect or missing. Setting headers manually.")
        data = pd.read_csv(input_csv, names=expected_columns, header=0)
    else:
        data = pd.read_csv(input_csv)

    return data


def aggregate_data(input_csv, output_csv):
    data = verify_and_load_csv(input_csv)

    aggregated_data = defaultdict(lambda: {'size': [], 'timestamp': [], 'directionality': [], 'label': 'unknown'})

    for _, row in data.iterrows():
        ip_src = row['ip_src']
        ip_dst = row['ip_dst']
        size = row['frame_len']
        timestamp = row['time_relative']

        direction = 1 if '10.' in ip_src else 0
        key = (ip_src, ip_dst)
        aggregated_data[key]['size'].append(size)
        aggregated_data[key]['timestamp'].append(timestamp)
        aggregated_data[key]['directionality'].append(direction)

        if is_linkedin_ip(ip_src) or is_linkedin_ip(ip_dst):
            aggregated_data[key]['label'] = 'linkedin'

    formatted_data = [['ip_src', 'ip_dst', 'size', 'timestamp', 'directionality', 'label']]
    for key, values in aggregated_data.items():
        ip_src, ip_dst = key
        size_json = json.dumps(values['size'])
        timestamp_json = json.dumps(values['timestamp'])
        directionality_json = json.dumps(values['directionality'])
        label = values['label']
        formatted_data.append([ip_src, ip_dst, size_json, timestamp_json, directionality_json, label])

    output_df = pd.DataFrame(formatted_data[1:], columns=formatted_data[0])
    output_df.to_csv(output_csv, index=False)

    print("Data aggregation complete. Output saved to {}".format(output_csv))


if __name__ == "__main__":
    input_csv = "C:\\Windows\\System32\\captured_data_again.csv"
    output_csv = "C:\\Users\\aisha\\Downloads\\aggregated_data.csv"

    if os.path.exists(input_csv):
        aggregate_data(input_csv, output_csv)
    else:
        print("Error: Input file {} not found.".format(input_csv))

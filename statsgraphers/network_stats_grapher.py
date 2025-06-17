#!/usr/bin/env python3

# <legal>
# Silent Sentinel
#
# Copyright 2025 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS
# TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE
# OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.
# CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT
# TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see LICENSE.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release
# and unlimited distribution. Please see Copyright notice for non-US Government
# use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM25-0550
# </legal>

import argparse
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, MaxNLocator
import os
import pandas as pd
from pyshark import FileCapture

BITS_PER_BYTE = 8

def extract_network_bandwidth_data(path_to_pcap_file: str, path_to_testharness_ip_file: str, path_to_testharness_ipv6_file: str):
    """
    Read the supplied .pcap network capture file and return data frames
    containing the inbound packet sizes and outbound packet sizes at the
    epoch timestamp each packet occurs.
    """

    try:
        with open(path_to_testharness_ip_file, 'r') as ip_address_file:
            ip_address = ip_address_file.read().strip()
    except FileNotFoundError:
        print(f"Error: File containing testharness container's IP address does not exist at {path_to_testharness_ip_file}")
        exit(1)

    try:
        with open(path_to_testharness_ipv6_file, 'r') as ipv6_address_file:
            ipv6_address = ipv6_address_file.read().strip()
    except FileNotFoundError:
        # Normal when IPv6 wasn't enabled
        ipv6_address = None

    # Store all packets that match inbound/outbound destination IP address with their timestamps and packet length (bytes)
    inbound_bandwidth_data_list = []
    outbound_bandwidth_data_list = []

    try:
        # Only parse packets that are in the IP layer (IPv4, or IPv6 if enabled) and have relevant IP addresses
        if ipv6_address:
            packet_display_filter = f"(ip and not ipv6 and (ip.src == {ip_address} || ip.dst == {ip_address})) || (ipv6 and (ipv6.src == {ipv6_address} || ipv6.dst == {ipv6_address}))"
        else:
            packet_display_filter = f"ip and not ipv6 and (ip.src == {ip_address} || ip.dst == {ip_address})"
        with FileCapture(
            path_to_pcap_file,
            display_filter=packet_display_filter,
            keep_packets=False,
            use_ek=True,
            include_raw=False) as capture:
            for current_packet in capture:
                if (hasattr(current_packet, 'ip') and current_packet.ip.dst.value == ip_address) or (ipv6_address and hasattr(current_packet, 'ipv6') and current_packet.ipv6.dst.value == ipv6_address):
                    timestamp = current_packet.sniff_timestamp
                    frame_length_bytes = current_packet.frame_info.len
                    next_inbound_bandwidth_row = {"timestamp": float(timestamp), "frameLengthBytes": int(frame_length_bytes)}
                    inbound_bandwidth_data_list.append(next_inbound_bandwidth_row)
                elif (hasattr(current_packet, 'ip') and current_packet.ip.src.value == ip_address) or (ipv6_address and hasattr(current_packet, 'ipv6') and current_packet.ipv6.src.value == ipv6_address):
                    timestamp = current_packet.sniff_timestamp
                    frame_length_bytes = current_packet.frame_info.len
                    next_outbound_bandwidth_row = {"timestamp": float(timestamp), "frameLengthBytes": int(frame_length_bytes)}
                    outbound_bandwidth_data_list.append(next_outbound_bandwidth_row)
    except FileNotFoundError:
        print(f"Error: .pcap file does not exist at {path_to_pcap_file}")
        raise

    # Ingest lists into data frames for easier arithmetic operations
    inbound_bandwidth_df = pd.DataFrame(inbound_bandwidth_data_list)
    outbound_bandwidth_df = pd.DataFrame(outbound_bandwidth_data_list)

    return inbound_bandwidth_df, outbound_bandwidth_df

def calculate_bits_per_second_values(packet_length_data: pd.DataFrame):
    """
    Calculate the data rates at a specified interval in N seconds. Returns a new
    data frame, where each row is a normalized time bucket interval with the
    bits per second data rate. The epoch timestamp in the first entry becomes
    t = 0, so we add the interval from t = 0 to make each subsequent time [0, 0 + interval, ...]
    """

    # Return a placeholder dataframe if there is no actual data
    if len(packet_length_data) == 0:
        placeholder_data = {
            "timestamp": [0],
            "bps": [0]
        }

        return pd.DataFrame(placeholder_data)

    binned_data_rates = packet_length_data.copy()

    # Normalize the timestamp values to t = 0, by subtracting the first epoch timestamp from every row
    inbound_t_zero_value = binned_data_rates["timestamp"][0]
    binned_data_rates["timestamp"] = binned_data_rates["timestamp"] - inbound_t_zero_value

    # Remove trailing decimal places, to deal with whole seconds
    binned_data_rates["timestamp"] = binned_data_rates["timestamp"].astype(int)

    # Sum the packet length values for each second worth of packet data
    binned_data_rates['bps'] = binned_data_rates.groupby('timestamp')['frameLengthBytes'].transform('sum')
    binned_data_rates.drop("frameLengthBytes", axis=1, inplace=True)
    binned_data_rates.drop_duplicates(inplace=True)

    # Calculate bits per second by converting bytes per second
    binned_data_rates["bps"] = binned_data_rates["bps"] * BITS_PER_BYTE
    return binned_data_rates

def scale_bps(value):
    """
    Convert bits/sec values into appropriate units for human readability
    """

    for unit in ['b', 'kb', 'Mb', 'Gb', 'Tb']:
        if value < 1000.0:
            return f"{value:.1f} {unit}ps"
        value /= 1000.0

    # If it's really large, handle Pb (petabits) as well
    return f"{value:.1f} Pbps"

def create_bandwidth_plot(inbound_data_rates: pd.DataFrame, outbound_data_rates: pd.DataFrame, vol_path: str):
    """
    Creates a graph .png file, plotting the inbound vs. outbound bandwidth usage in bits per second.
    This data is from the captured .pcap network traffic from the test harness.
    """

    max_inbound_data_rate = inbound_data_rates["bps"].max()
    max_outbound_data_rate = outbound_data_rates["bps"].max()

    fig, (ax1, ax2) = plt.subplots(nrows=2, ncols=1)

    # Plot data in the first subplot (top)
    ax1.plot(inbound_data_rates["timestamp"], inbound_data_rates["bps"], color='#00416a')
    ax1.fill_between(inbound_data_rates["timestamp"], inbound_data_rates["bps"], 0, color='#00416a', alpha=0.3)
    ax1.set_title("Inbound Data Rate vs. Time")
    ax1.set_xlabel("Time (sec)")
    ax1.set_ylabel("Bandwidth Data Rate")

    # Plot data in the second subplot (bottom)
    ax2.plot(outbound_data_rates["timestamp"], outbound_data_rates["bps"], color='#dba50f')
    ax2.fill_between(outbound_data_rates["timestamp"], outbound_data_rates["bps"], 0, color='#dba50f', alpha=0.3)
    ax2.set_title("Outbound Data Rate vs. Time")
    ax2.set_xlabel("Time (sec)")
    ax2.set_ylabel("Bandwidth Data Rate")

    # Display maximum data rate from other plot to show scale
    if max_outbound_data_rate < max_inbound_data_rate:
        ax1.axhline(y=max_outbound_data_rate, color='#c41230', linestyle='--', label=f'Max Outbound Rate = {scale_bps(max_outbound_data_rate)}')
        ax1.legend()
    else:
        ax2.axhline(y=max_inbound_data_rate, color='#c41230', linestyle='--', label=f'Max Inbound Rate = {scale_bps(max_inbound_data_rate)}')
        ax2.legend()

    # Configure the number and formatting of the y-axis tick values of all subplots
    for subplot_axis in fig.get_axes():
        subplot_axis.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=4, min_n_ticks=4))
        subplot_axis.yaxis.set_major_formatter(FuncFormatter(lambda x, _: scale_bps(x)))

    # Adjust layout to prevent overlap
    plt.tight_layout()

    # Save graph to .png format
    bandwidth_graph_filepath = os.path.join(vol_path, "network-bandwidth-graph.png")
    plt.savefig(bandwidth_graph_filepath)


if __name__ == '__main__':
    top_level_description = """
    This script calculates the data rates for the inbound vs. outbound traffic
    with respect to the testharness container. It generates graphs that can
    be included in Silent Sentinel reports.
    """

    parser = argparse.ArgumentParser(description=top_level_description)
    parser.add_argument('volume_path', type=str, help='Path to the volume-mounted directory containing intermediate output files')
    args = parser.parse_args()

    path_to_pcap_file = os.path.join(args.volume_path, "tcpdump.pcap")
    path_to_testharness_ip_file = os.path.join(args.volume_path, "testharness_ip_address.txt")
    path_to_testharness_ipv6_file = os.path.join(args.volume_path, "testharness_ipv6_address.txt")
    inbound_bandwidth_df, outbound_bandwidth_df = extract_network_bandwidth_data(path_to_pcap_file, path_to_testharness_ip_file, path_to_testharness_ipv6_file)

    inbound_binned_data_rates = calculate_bits_per_second_values(inbound_bandwidth_df)
    outbound_binned_data_rates = calculate_bits_per_second_values(outbound_bandwidth_df)
    create_bandwidth_plot(inbound_binned_data_rates, outbound_binned_data_rates, args.volume_path)

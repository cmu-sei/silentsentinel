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

def extract_diskio_data(path_to_diskio_file: str):
    """
    Read the supplied .csv file and return a data frame
    containing relevant statistics for read and write operations across all hard drives.
    """

    # Template for an empty data frame if certain errors happen
    placeholder_data = {
        "timestamp": [],
        "bytes_read/s": [],
        "bytes_written/s": []
    }

    try:
        io_datapoints = pd.read_csv(path_to_diskio_file, sep=',')
    except FileNotFoundError:
        print(f"Warning: .csv file does not exist at {path_to_diskio_file}")
        return pd.DataFrame(placeholder_data)

    # Return a placeholder dataframe if there is no actual data
    if len(io_datapoints) == 0:
        return pd.DataFrame(placeholder_data)

    # Normalize the bytes read and bytes written values, by subtracting the first row's values from every row
    t_zero_bytes_read_value = io_datapoints["bytes_read/s"][0]
    io_datapoints["bytes_read/s"] = io_datapoints["bytes_read/s"] - t_zero_bytes_read_value

    t_zero_bytes_written_value = io_datapoints["bytes_written/s"][0]
    io_datapoints["bytes_written/s"] = io_datapoints["bytes_written/s"] - t_zero_bytes_written_value

    # Transform each row by subtracting the previous row's values.
    # This converts the values to become the number of bytes are read/written
    # each second, rather than the cumulative total at this moment.
    io_datapoints = io_datapoints.diff()
    io_datapoints.fillna(0, inplace=True)

    # Add a column showing the timestamp, starting at t = 0 seconds
    io_datapoints.insert(0, 'timestamp', io_datapoints.index)

    return io_datapoints

def scale_bytes(value):
    """
    Convert bytes/sec values into appropriate units for human readability
    """

    for unit in ['bytes', 'KiB', 'MiB', 'GiB', 'TiB']:
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0

    # If it's really large, handle PB (petabytes) as well
    return f"{value:.1f} PiB"

def create_disk_performance_plot(io_statistics: pd.DataFrame, vol_path: str):
    """
    Creates a graph .png file, plotting amount of data read vs. written per second.
    """

    # If the data frame is empty, there is no data to create a plot.
    # Don't create an empty image file in this case.
    if len(io_statistics) == 0:
        return

    max_bytes_read_rate = io_statistics["bytes_read/s"].max()
    max_bytes_written_rate = io_statistics["bytes_written/s"].max()

    fig, (ax1, ax2) = plt.subplots(nrows=2, ncols=1)

    # Plot data in the first subplot (top)
    ax1.plot(io_statistics["timestamp"], io_statistics["bytes_read/s"], color='#00416a')
    ax1.fill_between(io_statistics["timestamp"], io_statistics["bytes_read/s"], 0, color='#00416a', alpha=0.3)
    ax1.set_title("Data Read from Disk vs. Time")
    ax1.set_xlabel("Time (sec)")
    ax1.set_ylabel("Data Read")

    # Plot data in the second subplot (bottom)
    ax2.plot(io_statistics["timestamp"], io_statistics["bytes_written/s"], color='#dba50f')
    ax2.fill_between(io_statistics["timestamp"], io_statistics["bytes_written/s"], 0, color='#dba50f', alpha=0.3)
    ax2.set_title("Data Written to Disk vs. Time")
    ax2.set_xlabel("Time (sec)")
    ax2.set_ylabel("Data Written")

    # Display maximum I/O throughput rate from other plot to show scale
    if max_bytes_written_rate < max_bytes_read_rate:
        ax1.axhline(y=max_bytes_written_rate, color='#c41230', linestyle='--', label=f'Max Data Written = {scale_bytes(max_bytes_written_rate)}/sec')
        ax1.legend()
    else:
        ax2.axhline(y=max_bytes_read_rate, color='#c41230', linestyle='--', label=f'Max Data Read = {scale_bytes(max_bytes_read_rate)}/sec')
        ax2.legend()

    # Configure the number and formatting of the y-axis tick values of all subplots
    for subplot_axis in fig.get_axes():
        subplot_axis.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=4, min_n_ticks=4))
        subplot_axis.yaxis.set_major_formatter(FuncFormatter(lambda x, _: scale_bytes(x)))

    # Adjust layout to prevent overlap
    plt.tight_layout()

    # Save graph to .png format
    disk_performance_graph_filepath = os.path.join(vol_path, "disk-performance-graph.png")
    plt.savefig(disk_performance_graph_filepath)


if __name__ == '__main__':
    top_level_description = """
    This script calculates the total I/O data rates for hard drive reading and writing
    with respect to the testharness container. It generates graphs that can
    be included in Silent Sentinel reports.
    """

    parser = argparse.ArgumentParser(description=top_level_description)
    parser.add_argument('volume_path', type=str, help='Path to the volume-mounted directory containing intermediate output files')
    args = parser.parse_args()

    path_to_diskio_file = os.path.join(args.volume_path, "diskio-output.csv")
    extracted_io_stats = extract_diskio_data(path_to_diskio_file)

    # If there is no data to plot, create a .placeholder file. This will add a line
    # in a generated report saying that there is no data in this section.
    if len(extracted_io_stats) == 0:
        disk_performance_placeholder_filepath = os.path.join(args.volume_path, "disk-performance-graph.placeholder")
        with open(disk_performance_placeholder_filepath, "w") as placeholder_file:
            placeholder_file.write("This section is intentionally blank, since there is no data to display. ")
            placeholder_file.write("No disk I/O data will be recorded by Silent Sentinel if the host operating system uses cgroups version 1.\n")
        exit(0)

    create_disk_performance_plot(extracted_io_stats, args.volume_path)

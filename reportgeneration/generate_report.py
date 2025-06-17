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
import json
import os
import re
import shlex
import shutil
import typing
from datetime import datetime
from subprocess import run, PIPE

TIMESTAMP_REGEX = re.compile(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.\d+")

def find_values_for_key(json_data, target_key: str):
    """
    Recursively search for a key in a nested JSON object and return its values.
    """

    results = []

    if isinstance(json_data, dict):
        for key, value in json_data.items():
            if key == target_key:
                # Capture the value for the matching key
                results.append(value)

            # Recursively look for the target key into the value
            results.extend(find_values_for_key(value, target_key))
    elif isinstance(json_data, list):
        for item in json_data:
            # Recursively look for the target key into the value
            results.extend(find_values_for_key(item, target_key))

    return results


def save_strace_data_as_json(strace_folder_path: str):
    """
    Read the data from strace and convert it to a JSON format using
    the b3 tool installed in the container
    """

    with open(os.path.join(strace_folder_path, 'strace.json'), 'w') as strace_parsed_file:
        with open(os.path.join(strace_folder_path, 'strace.out'), "r") as strace_output:
            parsing_process = run(['b3'], stdin=strace_output, stdout=strace_parsed_file)

    os.remove(os.path.join(strace_folder_path, 'strace.out'))


def create_analysis_tool_report_section(output_file: typing.TextIO, test_tool_name: str):
    """
    Create a new section for a provided analysis tool in the report.
    """

    test_tool_header_parts = test_tool_name.split('_', maxsplit=1)
    test_tool_section_header = test_tool_header_parts[0]
    output_file.write(f'## {test_tool_section_header} \n\n')


def create_analysis_tool_report_subsection(filepath: str, output_file: typing.TextIO, test_tool_name: str):
    """
    Create a new subsection for a provided analysis tool in the report. This helps
    organize multiple data entries for varied timestamps and differences found by
    the analysis tools in time-ordered sequence.
    """

    # Write sub-section header if a timestamp is present in the provided analysis tool name
    test_tool_header_parts = test_tool_name.split('_', maxsplit=1)
    if len(test_tool_header_parts) > 1 and re.search(TIMESTAMP_REGEX, test_tool_header_parts[1]):
        timestamp = test_tool_header_parts[1]
        timestamp = os.path.splitext(timestamp)[0]
        output_file.write(f'### Obtained Data at {timestamp}\n\n')
        return

    # Write sub-section header for the provided analysis tool's current file data.
    # This handles multiple files for an analysis tool.
    file_basename = os.path.basename(filepath)
    filename_root, filename_extension = os.path.splitext(file_basename)

    sequence_number = filename_root.partition(test_tool_name + '_')[2]
    if sequence_number.isnumeric():
        output_file.write(f'### Oneshot Instrumentation Increment {(int(sequence_number) + 1)}\n\n')
        return
    elif sequence_number.startswith("start_end"):
        output_file.write(f'### Differences Between First and Last Oneshot Instrumentation\n\n')
        return

    # Otherwise write literal value
    output_file.write(f'### {sequence_number} Differences\n\n')


def append_result_data_to_report(filepath: str, output_file: typing.TextIO):
    """
    Read data from a test results file, format the information, and append it to the report
    """

    if os.stat(filepath).st_size == 0:
        output_file.write("No changes/differences detected by this tool.\n\n")
        return

    if filepath.endswith('.diff'):
        output_file.write('```{.diff .numberlines}\n')
    elif filepath.endswith('.json'):
        output_file.write('```{.json .numberlines}\n')
    else:
        output_file.write('```{.bash .numberlines}\n')

    with open(filepath, "r") as file:
        last_line = None
        for line in file.readlines():
            output_file.write(line)
            last_line = line

        if not last_line.endswith('\n'):
            output_file.write('\n')
    output_file.write('```\n\n')


def append_plaintext_data_to_report(filepath: str, output_file: typing.TextIO):
    """
    Read data from a plain text file (e.g. a placeholder file), format the information,
    and append it to the report.
    """

    with open(filepath, "r") as data_file:
        shutil.copyfileobj(data_file, output_file)
    output_file.write('\n\n')


def insert_image_into_report(filepath: str, output_file: typing.TextIO, image_alt_text=""):
    """
    Insert an image file into the report. Images are limited to certain
    formats with predictable behavior.
    """

    # Adjust the relative filepath of the image's location, so it can be correctly
    # rendered by the Markdown file. The Markdown report is created up directory
    # up from where the image files live.
    relative_image_filepath = os.path.relpath(filepath, start=os.path.dirname(output_file.name))

    # Provide a default alternative text string for an image caption
    if not image_alt_text:
        image_alt_text = os.path.basename(relative_image_filepath)

    embedded_image_markdown = f'![{image_alt_text}]({relative_image_filepath})'
    output_file.write(embedded_image_markdown)
    output_file.write("\n\n")


def create_diff_files(dir_path: str, test_tool_name: str):
    """
    Create .diff files from an ordered list of output files/subdirectories in the provided directory.
    The ordered list of directory items are sorted from oldest to newest creation time,
    ensuring that each .diff file is an incremental step of what changed.
    """

    directory_items = []
    if test_tool_name == "crontabs":
        # Get a list of subdirectories to compare their differences
        directory_items = [item for item in os.listdir(dir_path) if os.path.isdir(os.path.join(dir_path, item))]
    else:
        # Get a list of files to compare their differences, skipping error files
        directory_items = list(filter(lambda file: not file.endswith('.err'), os.listdir(dir_path)))
    directory_items.sort()

    # Iterate through all files to create incremental diff files
    for idx, path in enumerate(directory_items):
        if idx + 1 < len(directory_items):
            with open(os.path.join(dir_path, f'{test_tool_name}_{idx}.diff'), 'w') as diff_file:
                diff_proc = run(['diff',
                                 '--unified=0',
                                 '--suppress-common-lines',
                                 '--recursive',
                                 '--new-file',
                                 '--text',
                                 os.path.join(dir_path, path),
                                 os.path.join(dir_path, directory_items[idx + 1])],
                                stdout=PIPE,
                                text=True)

                # Remove the diff command, since it clutters the output
                sed_proc_remove_cmd = run(['sed',
                                           's/^diff .*$/\\n/'],
                                          input=diff_proc.stdout,
                                          stdout=diff_file,
                                          text=True)

    # Create an overall start-to-end diff file (irrelevant for just two files)
    if len(directory_items) > 2:
        with open(os.path.join(dir_path, f'{test_tool_name}_start_end.diff'), 'w') as diff_start_end:
            diff_start_end_proc = run(
                ['diff',
                 '--unified=0',
                 '--suppress-common-lines',
                 '--recursive',
                 '--new-file',
                 '--text',
                 os.path.join(dir_path, directory_items[0]),
                 os.path.join(dir_path, directory_items[len(directory_items) - 1])],
                stdout=PIPE,
                text=True)

            # Remove the diff command, since it clutters the output
            sed_start_end_remove_cmd = run(['sed',
                                            's/^diff .*$/\\n/'],
                                           input=diff_start_end_proc.stdout,
                                           stdout=diff_start_end,
                                           text=True)


def check_if_all_extension_files_empty(directory: str, file_extension: str):
    """
    Returns True if all files with provided extension are empty,
    False if one or more are non-empty
    """

    all_empty = all(
        os.path.getsize(os.path.join(directory, file)) == 0
        for file in os.listdir(directory)
        if file.endswith(file_extension)
    )

    return all_empty


def filter_ps_data(ps_folder_path: str):
    """
    Filter the data within the ps output file, so that all testharness information is removed.
    We are only interested in the effects of the command under test.
    """

    output_files_list = list(filter(lambda file: not file.endswith('.err'), os.listdir(ps_folder_path)))
    for f in output_files_list:
        with open(os.path.join(ps_folder_path, f), "r") as output_file:
            with open(os.path.join(ps_folder_path, f'{f[:-4]}_filtered.out'), 'w') as filtered_file:
                for line in output_file.readlines():
                    if 'tcpdump' not in line:
                        filtered_file.write(line)
        os.remove(os.path.join(ps_folder_path, f))


def reduce_suricata_event_data(suricata_filepath: str):
    """
    Read the JSON objects in the Suricata Extensible Event Format file
    and create a reduced subset of relevant information in a new file.
    This includes the number of rule failures, any alert event types,
    and any anomaly event types.
    """

    event_payloads = []
    raw_suricata_events_filename = os.path.join(suricata_filepath, "raw-suricata-events.log")
    with open(raw_suricata_events_filename, 'r') as events_file:
        for current_line in events_file:
            current_line = current_line.strip()
            if current_line:
                event_payloads.append(json.loads(current_line))

    # Get the total number of suricata rules, number of rule failures, and number of skipped rules
    rule_data = {}
    rule_data['rules_loaded'] = find_values_for_key(event_payloads, 'rules_loaded')[0]
    rule_data['rules_failed'] = find_values_for_key(event_payloads, 'rules_failed')[0]
    rule_data['rules_skipped'] = find_values_for_key(event_payloads, 'rules_skipped')[0]

    # Only keep any alert and and anomaly event types, discarding the rest of the data
    alert_events = []
    anomaly_events = []
    for current_event in event_payloads:
        if current_event['event_type'] == "alert":
            alert_events.append(current_event)
        elif current_event['event_type'] == "anomaly":
            anomaly_events.append(current_event)

    # Overwrite the suricata events file, containing only the desired subset of information
    with open(os.path.join(suricata_filepath, 'suricata-events.out'), 'w') as events_subset_file:
        events_subset_file.write('-' * 79 + "\n")
        events_subset_file.write("Rule statistics for processed network capture data:\n")
        events_subset_file.write(f"Total rules loaded: {rule_data['rules_loaded']}\n")
        events_subset_file.write(f"Number of failed rules: {rule_data['rules_failed']}\n")
        events_subset_file.write(f"Number of skipped rules: {rule_data['rules_skipped']}\n")
        events_subset_file.write('-' * 79 + "\n")

        events_subset_file.write("Alerts which match Suricata rules:\n")
        for alert in alert_events:
            alert_json_string = json.dumps(alert, indent=4)
            events_subset_file.write(alert_json_string + '\n')
        events_subset_file.write('-' * 79 + "\n")

        events_subset_file.write("Anomalies (unexpected protocol lengths, values, or other conditions):\n")
        for anomaly in anomaly_events:
            anomaly_json_string = json.dumps(anomaly, indent=4)
            events_subset_file.write(anomaly_json_string + '\n')


def open_report_md(vol_path: str, now: datetime):
    try:
        return open(f'{vol_path}/silentsentinel_report_{now.strftime("%Y-%m-%d_%H-%M-%S")}.md', "x")
    except FileExistsError:
        # Use of an underscore rather than a dot after seconds is important so that this case sorts after the above case
        return open(f'{vol_path}/silentsentinel_report_{now.strftime("%Y-%m-%d_%H-%M-%S_%f")}.md', "x")


def get_max_bandwidth_capacity(volume_path: str):
    """
    Read the designated file containing the testharness network interface's maximum
    bandwidth capacity. Format a sentence explaining this and return it.
    """

    path_to_max_bandwidth_capacity_file = os.path.join(volume_path, "testharness", "testharness_max_bandwidth.txt")

    with open(path_to_max_bandwidth_capacity_file, 'r') as max_bandwidth_file:
        maximum_bandwidth_capacity = max_bandwidth_file.read().strip()

    return f"The maximum bandwidth capacity of the network interface is {maximum_bandwidth_capacity}"


def main(vol_path: str, testharness_args: typing.List[str]):
    """
    Driver method for this script, which creates a Markdown report file from the aggregated output
    from the test harness. Intermediate output files generated from the test harness serve as
    input data for the report.
    """

    # Read the JSON config file if it exists in this container
    silent_sentinel_config_data = {}
    try:
        with open("/config.json", "r") as config_file:
            silent_sentinel_config_data = json.load(config_file)
    except FileNotFoundError:
        pass

    now = datetime.now()
    with open_report_md(vol_path, now) as output_file:
        output_file.write("# Test Detail\n\n")

        if silent_sentinel_config_data:
            output_file.write(f'This report contains the results of the automated testing performed with the provided config file:\n\n')
            output_file.write(f'```json\n')
            output_file.write(f'{json.dumps(silent_sentinel_config_data, indent=4)}\n')
            output_file.write(f'```\n\n')
        else:
            output_file.write(f'This report contains the results of the automated testing performed on this command with the specified options:\n\n')
            output_file.write(f'```bash\n')
            output_file.write(f'{" ".join([shlex.quote(x) for x in testharness_args])}\n')
            output_file.write(f'```\n\n')

        output_file.write(f'This report was generated at: {now.strftime("%Y-%m-%d %H:%M:%S.%f")}\n\n')

        # Iterate through the contents of the subdirectories in the mounted volume. Data contained
        # here is then processed and added to the report. It is assumed that anything in
        # these directories is intentionally created by Silent Sentinel.
        for volume_mount_subdirectory in ("testharness", "listeningpost"):
            output_file.write('\n---\n\n')
            output_file.write(f'# Analysis of {volume_mount_subdirectory}\n\n')

            # Get full path to current volume mount subdirectory
            volume_mount_subdir_path = os.path.abspath(os.path.join(vol_path, volume_mount_subdirectory))

            # Convert the strace results into a more parsable JSON format
            if "strace.out" in os.listdir(volume_mount_subdir_path):
                save_strace_data_as_json(strace_folder_path=volume_mount_subdir_path)

            # Reduce the suricata event data to a subset
            if "raw-suricata-events.log" in os.listdir(volume_mount_subdir_path):
                reduce_suricata_event_data(suricata_filepath=volume_mount_subdir_path)

            for entry in os.scandir(volume_mount_subdir_path):
                # Get the name of the tool for the file/directory
                test_tool_name, test_tool_file_extension = os.path.splitext(entry.name)
                if entry.is_dir():
                    test_tool_name = entry.name

                    # Run ps output files through filter to remove testharness output
                    if test_tool_name == "ps":
                        filter_ps_data(entry.path)

                    # Only create a report section when there are results in the subdirectory
                    if not os.listdir(entry):
                        continue

                    create_analysis_tool_report_section(output_file, test_tool_name)

                    # Write file results for analysis tool subdirectory data
                    if test_tool_name == "coredump-strings":
                        for current_file in os.scandir(entry.path):
                            if current_file.name.startswith('coredump-strings_') and os.path.splitext(current_file.name)[1] == '.out':
                                create_analysis_tool_report_subsection(current_file.path, output_file, current_file.name)
                                append_result_data_to_report(current_file.path, output_file)
                        continue

                    create_diff_files(entry.path, test_tool_name)
                    all_diff_files_empty = check_if_all_extension_files_empty(entry.path, ".diff")
                    if all_diff_files_empty:
                        output_file.write("No changes/differences detected by this tool.\n\n")
                    else:
                        for current_file in os.scandir(entry.path):
                            if os.path.splitext(current_file.name)[1] == '.diff':
                                create_analysis_tool_report_subsection(current_file.path, output_file, test_tool_name)
                                append_result_data_to_report(current_file.path, output_file)
                elif test_tool_file_extension == '.placeholder':
                    create_analysis_tool_report_section(output_file, test_tool_name)
                    append_plaintext_data_to_report(entry.path, output_file)
                elif test_tool_file_extension in ('.json', '.out', '.diff'):
                    # Skip pcap files, since this data is refined through other means (e.g. suricata)
                    if test_tool_name != "pcap":
                        create_analysis_tool_report_section(output_file, test_tool_name)
                        append_result_data_to_report(entry.path, output_file)
                elif test_tool_file_extension in ('.png', '.jpg'):
                    create_analysis_tool_report_section(output_file, test_tool_name)
                    alternative_text = ""
                    if test_tool_name == "network-bandwidth-graph":
                        alternative_text = "Network Bandwidth: " + get_max_bandwidth_capacity(vol_path)
                    elif test_tool_name == "disk-performance-graph":
                        alternative_text = "Disk I/O Performance"
                    insert_image_into_report(entry.path, output_file, alternative_text)


if __name__ == '__main__':
    top_level_description = """
    This script collects relevant output data from the Silent Sentinel test harness,
    and creates a report in Markdown format.
    """

    parser = argparse.ArgumentParser(description=top_level_description)
    parser.add_argument('volume_path', type=str, help='Path to the volume-mounted directory containing intermediate output files')
    parser.add_argument('test_harness_args', nargs=argparse.REMAINDER, help='The arguments supplied to Silent Sentinel and the command under test when invoking the test harness')
    args = parser.parse_args()

    main(args.volume_path, args.test_harness_args)

#!/bin/bash

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

# Generate ipfix files with DPI and APPLABEL to be saved as artifacts and be analyzed if needed
yaf --in /vol/testharness/tcpdump.pcap --out /vol/testharness/pcap.ipfix --log /vol/testharness/yaf.log --verbose --max-payload=2048 --silk --applabel --dpi
yaf --in /vol/listeningpost/tcpdump.pcap --out /vol/listeningpost/pcap.ipfix --log /vol/listeningpost/yaf.log --verbose --max-payload=2048 --silk --applabel --dpi

# Generate simple ipfix files for yafscii to ingest
yaf --in /vol/testharness/tcpdump.pcap --out /vol/testharness/simple_pcap.ipfix --log /vol/testharness/yaf.log --verbose --max-payload=2048 --silk
yaf --in /vol/listeningpost/tcpdump.pcap --out /vol/listeningpost/simple_pcap.ipfix --log /vol/listeningpost/yaf.log --verbose --max-payload=2048 --silk

# Create JSON files from DPI and APPLABEL ipfix files
ipfix2json --in=/vol/testharness/pcap.ipfix --out=/vol/testharness/pcap.json
ipfix2json --in=/vol/listeningpost/pcap.ipfix --out=/vol/listeningpost/pcap.json

# Create .txt files from yafscii for addition to report
yafscii --in=/vol/testharness/simple_pcap.ipfix --out=/vol/testharness/netflow.out --log /vol/testharness/yaf.log --verbose
yafscii --in=/vol/listeningpost/simple_pcap.ipfix --out=/vol/listeningpost/netflow.out --log /vol/listeningpost/yaf.log --verbose

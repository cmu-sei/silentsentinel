#!/bin/sh

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

# This script saves files for the cumulative data read to and written from all hard drives
# accessible to a container's control group (cgroup). Output is saved into a .csv file.

echo "bytes_read/s,bytes_written/s" > /vol/testharness/diskio-output.csv

while true; do
    awk '{
        split($2, a, "="); rbytes_sum += a[2]
        split($3, b, "="); wbytes_sum += b[2]
    }
    END {
        print rbytes_sum","wbytes_sum;
    }' /sys/fs/cgroup/io.stat >> /vol/testharness/diskio-output.csv

    sleep 1
done

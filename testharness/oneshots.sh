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

: "${core_dump_analysis_enabled:?}"

# Use gdb to generate a coredump, analyze the strings output, and write to /vol/testharness.
# Check that the tool-under-test.pid file and the dirty words list file exist before trying to connect a gdb session to it.
analyze_strings_in_coredump() {
  tool_under_test_pid_file="/run/tool-under-test-pid.txt"
  if [ ! -f "$tool_under_test_pid_file" ]; then
    return 1
  fi

  coredump_strings_out_file=/vol/testharness/coredump-strings/coredump-strings_$now.out
  coredump_strings_err_file=/vol/testharness/coredump-strings/coredump-strings_$now.err
  if [ ! -f /vol/wordlist ]; then
    echo 'The core dump strings analysis was not run.' > "$coredump_strings_out_file"
    : > "$coredump_strings_err_file"
    return 2
  fi

  tool_under_test_pid=$(cat "$tool_under_test_pid_file")
  path_to_coredump="/vol/testharness/tool-under-test-coredump_$now.core"
  gdb -q -p "$tool_under_test_pid" --batch -ex "generate-core-file $path_to_coredump"

  # From the generated core dump, analyze string data for 'dirty words'
  echo 'The strings analysis detected the following matches in the provided dirty word list:' > "$coredump_strings_out_file"
  (strings "$path_to_coredump" | grep -Ff /vol/wordlist) >> "$coredump_strings_out_file" 2>"$coredump_strings_err_file"
  if [ "$?" -eq 1 ]; then
    echo 'The strings analysis did not detect any matches in the provided dirty word list.' > "$coredump_strings_out_file"
  fi
}

setup_oneshot_subdir() {
  rm -rf "/vol/testharness/$1/"
  mkdir "/vol/testharness/$1/"
  chown "$owner" "/vol/testharness/$1/"
}

# Main part of script
owner=$(stat -c %u:%g /vol/testharness/)
for i in netstat ps iptables ifconfig path crontabs memory-stat cpu-stat coredump-strings; do
  setup_oneshot_subdir "$i"
done
if [ -d /vol/custom_oneshots ]; then
  for i in /vol/custom_oneshots/*; do
    if [ -x "$i" ]; then
      setup_oneshot_subdir "${i##*/}"
    fi
  done
fi
while true; do
  cat /run/oneshots_trigger > /dev/null
  now="$(stat -L -c %y /proc/self | awk '{ gsub(":", "-"); print $1 "_" $2 }')"
  if [ -d /vol/custom_oneshots ]; then
    for i in /vol/custom_oneshots/*; do
      if [ -x "$i" ]; then
        "$i" > "/vol/testharness/${i##*/}/$now.out" 2>"/vol/testharness/${i##*/}/$now.err"
     fi
    done
  fi
  netstat -tulpn > "/vol/testharness/netstat/$now.out" 2>"/vol/testharness/netstat/$now.err"
  ps -ef > "/vol/testharness/ps/$now.out" 2>"/vol/testharness/ps/$now.err"
  iptables-save -c > "/vol/testharness/iptables/$now.out" 2>"/vol/testharness/iptables/$now.err"
  ifconfig -a > "/vol/testharness/ifconfig/$now.out" 2>"/vol/testharness/ifconfig/$now.err"
  # shellcheck disable=SC2016 # We want the PATH variable to expand inside of the su
  su - -c 'echo "$PATH"' > "/vol/testharness/path/$now.out" 2>"/vol/testharness/path/$now.err"

  # Take a snapshot of cron files into a subdirectory with the current timestamp.
  # Creating a tar archive gathers the needed files, then extracts them into a directory tree with their
  # original file paths intact. This helps to easily diff the directory structure.
  crontab_destination_dir=/vol/testharness/crontabs/$now/
  mkdir -p "$crontab_destination_dir"
  (tar -c /etc/crontab /etc/anacrontab /etc/cron.* /var/spool/cron | tar -x -C "$crontab_destination_dir") 2>/dev/null
  chown -R "$owner" "$crontab_destination_dir"

  if [ -f /sys/fs/cgroup/memory.stat ]; then
    # v2 cgroups
    cat /sys/fs/cgroup/memory.stat > "/vol/testharness/memory-stat/$now.out" 2>"/vol/testharness/memory-stat/$now.err"
  else
    # v1 cgroups
    cat /sys/fs/cgroup/memory/memory.stat > "/vol/testharness/memory-stat/$now.out" 2>"/vol/testharness/memory-stat/$now.err"
  fi

  if [ -f /sys/fs/cgroup/cpu.stat ]; then
    # v2 cgroups
    cat /sys/fs/cgroup/cpu.stat > "/vol/testharness/cpu-stat/$now.out" 2>"/vol/testharness/cpu-stat/$now.err"
  else
    # v1 cgroups
    # these don't have the most important values in this file, so emulate the v2 output format with them
    printf 'usage_usec %s\n' "$(( $(cat /sys/fs/cgroup/cpu/cpuacct.usage) / 1000 ))" > "/vol/testharness/cpu-stat/$now.out" 2>"/vol/testharness/cpu-stat/$now.err"
    printf 'user_usec %s\n' "$(( $(cat /sys/fs/cgroup/cpu/cpuacct.usage_user) / 1000 ))" >> "/vol/testharness/cpu-stat/$now.out" 2>>"/vol/testharness/cpu-stat/$now.err"
    printf 'system_usec %s\n' "$(( $(cat /sys/fs/cgroup/cpu/cpuacct.usage_sys) / 1000 ))" >> "/vol/testharness/cpu-stat/$now.out" 2>>"/vol/testharness/cpu-stat/$now.err"
    cat /sys/fs/cgroup/cpu/cpu.stat >> "/vol/testharness/cpu-stat/$now.out" 2>>"/vol/testharness/cpu-stat/$now.err"
  fi

  if [ "$core_dump_analysis_enabled" -ne 0 ]; then
    analyze_strings_in_coredump
  fi

  echo 'done' > /run/oneshots_complete
done

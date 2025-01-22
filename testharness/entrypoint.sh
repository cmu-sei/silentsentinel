#!/bin/sh

# <legal>
# Silent Sentinel
# 
# Copyright 2024 Carnegie Mellon University.
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
# and unlimited distribution.  Please see Copyright notice for non-US Government
# use and distribution.
# 
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
# 
# DM24-1586
# </legal>

: "${clamscan_enabled:?}" "${pspy_enabled:?}" "${strace_enabled:?}"

if [ ! -d /vol ]; then
  echo 'You need to mount /vol!'
  exit 1
fi
rm -rf /vol/testharness/
mkdir /vol/testharness/
chown "$(stat -c %u:%g /vol/)" /vol/testharness/

strings_out_file=/vol/testharness/strings.out
strings_err_file=/vol/testharness/strings.err
if [ -f /vol/wordlist ]; then
  echo 'The strings analysis detected the following matches in the provided dirty word list:' > $strings_out_file
  (strings "$(command -v "$1")" | grep -Ff /vol/wordlist) >> $strings_out_file 2>$strings_err_file
  if [ "$?" -eq 1 ]; then
    echo 'The strings analysis did not detect any matches in the provided dirty word list.' > $strings_out_file
  fi
else
  echo 'The strings analysis was not run.' > $strings_out_file
  : > $strings_err_file
fi

if [ "$clamscan_enabled" -ne 0 ]; then
  clamscan "$(command -v "$1")" > /vol/testharness/clamscan.out 2>/vol/testharness/clamscan.err
fi
tcpdump --immediate-mode -vvvnn -w /vol/testharness/tcpdump.pcap 2>/vol/testharness/tcpdump.err &
tcpdump_pid=$!
while [ ! -f /vol/testharness/tcpdump.pcap ]; do
  sleep 0.01
done

if [ "$pspy_enabled" -ne 0 ]; then
  mkfifo /run/pspyfifo
  cat /run/pspyfifo > /dev/null &
  cat_pid=$!
  pspy64 --color=0 -pf -i 1000 3> /run/pspyfifo 2> /vol/testharness/pspy.err > /vol/testharness/pspy.out &
  pspy64_pid=$!
  wait "$cat_pid"
  rm /run/pspyfifo
fi
mkfifo /run/oneshots_trigger
mkfifo /run/oneshots_complete

/oneshots.sh &
# Run oneshots to get a baseline of statistics before running the tool under test
echo go > /run/oneshots_trigger
cat /run/oneshots_complete > /dev/null

# Depending on the args provided, either run strace or just run the tool under test
if [ "$strace_enabled" -eq 1 ]; then
  strace -f -o /vol/testharness/strace.out "$@"
else
  # Run "$@", but save the pid to /run/tool-under-test-pid.txt, using subshells so we know it in advance without having to background
  (sh -c 'echo "$PPID"' > /run/tool-under-test-pid.txt; exec "$@")

  # Since we didn't background, as soon as we get here, the tool under test has exited, so its pid file is stale and should be removed
  rm /run/tool-under-test-pid.txt
fi

# Run oneshots after the tool under test finishes, so we can see what changed from the test run
echo go > /run/oneshots_trigger
cat /run/oneshots_complete > /dev/null

if [ "$pspy_enabled" -ne 0 ]; then
  kill "$pspy64_pid"
  # work around a bug in pspy64 where it misses signals sometimes
  sleep 1
  if kill "$pspy64_pid" 2>/dev/null; then
    sleep 1
    if kill "$pspy64_pid" 2>/dev/null; then
      sleep 1
      kill -9 "$pspy64_pid" 2>/dev/null
    fi
  fi
  wait "$pspy64_pid"
fi
kill "$tcpdump_pid"
wait "$tcpdump_pid"

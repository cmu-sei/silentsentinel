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

: "${clamscan_enabled:?}"

if [ ! -d /vol ]; then
  echo 'You need to mount /vol!'
  exit 1
fi

clamscan_output_file="/vol/testharness/clamscan.out"

# Perform YARA rule matching if a rules.yar file exists in the /vol directory
yara_enabled=0
yara_output_file="/vol/testharness/yara-rule-matches.out"
if [ -f "/vol/rules.yar" ]; then
  yara_enabled=1
else
  echo 'YARA was not run.' > "$yara_output_file"
fi

# Perform strings analysis if a "dirty words list" file exists in the /vol directory
strings_analysis_enabled=0
strings_output_file=/vol/testharness/strings.out
strings_err_file=/vol/testharness/strings.err
if [ -f "/vol/wordlist" ]; then
  strings_analysis_enabled=1
else
  echo 'The strings analysis was not run.' > $strings_output_file
  : > $strings_err_file
fi

# Determine where to apply static analysis tools (either overridden paths or
# the default 1st argument of the tool under test)
analysis_tool_targets=("$@")
if [ "$#" -eq 0 ]; then
  DEFAULT_ANALYSIS_TARGET=$(command -v "$default_analysis_target" 2>/dev/null)
  analysis_tool_targets=("$DEFAULT_ANALYSIS_TARGET")
fi

echo "Provided analysis target paths: ${analysis_tool_targets[@]}"
for target in "${analysis_tool_targets[@]}"
do
    if [[ ! -e "$target" ]]; then
        echo "Skipping static analysis on $target, since it does not exist"
        continue
    fi

    if [ "$clamscan_enabled" -ne 0 ]; then
        clamscan -r "$target" >> "$clamscan_output_file" 2>>/vol/testharness/clamscan.err
        echo >> "$clamscan_output_file"
    fi

    if [ "$yara_enabled" -ne 0 ]; then
        yara --print-meta --print-strings --fail-on-warnings /vol/rules.yar "$target" >> "$yara_output_file"
    fi

    if [ "$strings_analysis_enabled" -ne 0 ]; then
        if [ -f "$target" ]; then
            (strings "$target" | grep -Ff /vol/wordlist) >> $strings_output_file 2>>$strings_err_file
        elif [ -d "$target" ]; then
            find "$target" -type f -exec strings '{}' + | grep -Ff /vol/wordlist >> $strings_output_file 2>>$strings_err_file
        fi
    fi
done

# Add sentence explaining YARA results if we have some matched rules
if [ "$yara_enabled" -ne 0 ]; then
    if [ -s "$yara_output_file" ]; then
        temp_yara_matches_filename=/vol/testharness/temp-yara-rule-matches.out
        mv "$yara_output_file" "$temp_yara_matches_filename"
        echo 'The YARA scan detected the following match(es) in the provided rules:' > "$yara_output_file"
        echo >> "$yara_output_file"
        cat "$temp_yara_matches_filename" >> "$yara_output_file"
        rm "$temp_yara_matches_filename"
    else
        echo "The YARA scan did not detect any matches in the provided rules." > "$yara_output_file"
    fi
fi

# Add sentence explaining string analysis results if we have some matched any dirty words
if [ "$strings_analysis_enabled" -ne 0 ]; then
    if [ -s "$strings_output_file" ]; then
        temp_string_matches_filename=/vol/testharness/temp-string-matches.out
        mv "$strings_output_file" "$temp_string_matches_filename"
        echo 'The strings analysis detected the following matches in the provided dirty word list:' > $strings_output_file
        echo >> "$strings_output_file"
        cat "$temp_string_matches_filename" >> "$strings_output_file"
        rm "$temp_string_matches_filename"
    else
        echo 'The strings analysis did not detect any matches in the provided dirty word list.' > $strings_output_file
    fi
fi

#!/bin/bash

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

print_usage() {
  local msg=$1
  local exit_code=$2

  echo "$msg"
  echo 
  echo "Silent Sentinel Usage"
  echo "$0 [-h] | [-c path/to/config.json] | [-C] [-P] [-S] [-U] [-d] [-r n/m/a] [-t TAG] <VOLUME_MOUNT_DIRECTORY> <TOOL_UNDER_TEST>"
  printf '%s\n' '-c: Specify path to config.json file containing all Silent Sentinel settings'
  printf '%s\n' '-C: Disable clamscan'
  printf '%s\n' '-P: Disable PSPY'
  printf '%s\n' '-S: Disable STRACE'
  printf '%s\n' '-U: Disable Suricata'
  printf '%s\n' '-d: Enable analyzing string data from a core dump'
  printf '%s\n' '-r: Generate specified report formats: n - no report, m - markdown report, or a - all reports (default, markdown and pdf)'
  printf '%s\n' '-t: Run instrumentation in specified tag of the testharness and listeningpost images during runtime (default: debian)'
  printf '%s\n' '-h: Show usage documentation'
  echo
  echo "See README.md for the list of supported tags."
  echo "To run strings analysis create a file called 'wordlist' in the directory being mounted. (One search term per line in the file)"
  exit "$exit_code"
}

# Allow for replacement containerization command instead of Docker (e.g. podman)
: "${docker_compose:=docker compose}"

if ! command -v docker > /dev/null; then
  echo "Error - the 'docker' command does not exist. Please install it."
  exit 1
fi
if ! docker version > /dev/null; then
  echo "Error - the 'docker' command exists, but running the 'docker version' command failed. Please ensure that the Docker daemon is running, that your user account is in a group allowed to interact with it, and that you've logged out and back in (or rebooted) since being added to the group."
  exit 1
fi
if ! $docker_compose version > /dev/null 2>&1; then
  echo "Error - running the '$docker_compose version' command failed. This probably means that the $docker_compose plugin isn't installed. Please install it."
  exit 1
fi

export config_file_path=""
volpath=""
tool_under_test_plus_args=""
f=(-p silentsentinel -f docker-compose.yml)

export clamscan_enabled=1
export core_dump_analysis_enabled=0
export pspy_enabled=1
export strace_enabled=1
export suricata_enabled=1
export kata_enabled=0
report_generation="a"
export tag=debian

while getopts 'c:kt:r:SPCUdh' option; do
  case $option in
    h)
      print_usage "" 0
      ;;
    c)
      # When running the -c path/to/config_file option, no other command flags are allowed.
      # Return an error code if any additional flags are passed besides this.
      if [ $# -ne 2 ]; then
        print_usage "Error - When running Silent Sentinel with -c /path/to/config_file, you cannot provide any other command line options" 1
      fi

      # Check if path/to/config.json exists. If so, resolve to full path for correct docker compose mount
      export config_file_path="$OPTARG"
      if [ ! -f "$config_file_path" ]; then
        print_usage "Error - Config file does not exist at provided path" 1
      fi
      config_file_path="$(realpath -- "$config_file_path")"

      if ! command -v jq > /dev/null; then
        print_usage "Error - jq must be installed to use Silent Sentinel's -c option" 1
      fi
      ;;
    S)
      export strace_enabled=0
      ;;
    P)
      export pspy_enabled=0
      ;;
    C)
      export clamscan_enabled=0
      ;;
    d)
      export core_dump_analysis_enabled=1
      ;;
    U)
      export suricata_enabled=0
      ;;
    k)
      # Kata functionality is a beta feature and not fully functional
      f+=(-f docker-compose.kata.yml)
      export kata_enabled=1
      ;;
    t)
      export tag=$OPTARG
      ;;
    r)
      case $OPTARG in
        n|m|a)
          report_generation=$OPTARG
          ;;
        *)
          print_usage "Error - Invalid argument to -r option" 1
          ;;
      esac
      ;;
    \?)
      print_usage "" 1
      ;;
  esac
done

# Assign Silent Sentinel arguments into separate array (excluding silentsentinel.sh itself)
# This is needed for displaying in generated reports
silent_sentinel_command_flags=("${@:1:$((OPTIND - 1))}")

# Clear away all optional Silent Sentinel arguments, since already processed
shift "$((OPTIND - 1))"

# If the user passes a valid config file, use its values.
# Otherwise, use the provided command line arguments.
if [ -n "$config_file_path" ]; then
  # Populate variables from the config file to control script behavior
  volpath=$(jq -r '.volumeMountDirectory' "$config_file_path")
  volpath="$(realpath -- "$volpath")"

  # Assign tool under test with its arguments into a Bash array
  # to make it easier to pass to subsequent Docker commands.
  # The mapfile command handles newline characters embedded in the tool under test arguments.
  # jq 1.7 includes the '--raw-output0' option that would allow this to be simplified, so we should
  # switch to that once all non-EOL versions of Linux distros we support upgrade to it
  mapfile -d '' -t tool_under_test_plus_args < <(jq -j '.toolUnderTest[] | . + "\u0000"' "$config_file_path")

  # Determine which services Silent Sentinel will run
  export clamscan_enabled=$(jq -r '.analysisTools.clamscan | if . then 1 else 0 end' "$config_file_path")
  export core_dump_analysis_enabled=$(jq -r '.analysisTools.coreDumps | if . then 1 else 0 end' "$config_file_path")
  export pspy_enabled=$(jq -r '.analysisTools.pspy | if . then 1 else 0 end' "$config_file_path")
  export strace_enabled=$(jq -r '.analysisTools.strace | if . then 1 else 0 end' "$config_file_path")
  export suricata_enabled=$(jq -r '.analysisTools.suricata | if . then 1 else 0 end' "$config_file_path")
  export tag=$(jq -r '.tag' "$config_file_path")

  # Read format field and convert to single character command line format
  report_generation=$(jq -r '.reportFormat' "$config_file_path")
  case $report_generation in
    "all")
      report_generation="a"
      ;;
    "markdown")
      report_generation="m"
      ;;
    "none")
      report_generation="n"
      ;;
    *)
      print_usage "Error - Invalid argument for the reportFormat field" 1
      ;;
  esac
else
  # Passing less than 2 positional arguments will fail to run the tool under test
  if [ $# -lt 2 ]; then
    print_usage "Error - Required arguments <VOLUME_MOUNT_DIRECTORY> and/or <TOOL_UNDER_TEST> arguments are missing" 1
  fi

  volpath="$(realpath -- "$1")"
  shift 1

  # Assign tool under test with its arguments into an array
  # to make it easier to pass to subsequent Docker commands
  tool_under_test_plus_args=("$@")
fi

# Ensure that the volume mounted directory exists before it is mounted to the container
export volpath
test -d "$volpath" || mkdir "$volpath"

# Ensure that both core dump string analysis and strace are not both enabled
# These are mutually-exclusive options, since strace can interfere with a process-attached core dump.
if [ "$strace_enabled" -eq 1 ] && [ "$core_dump_analysis_enabled" -eq 1 ]; then
  print_usage "Error - core dump analysis and strace features are mutually exclusive. If you would like to generate strace output, omit -d (no core dump is produced). strace is activated by default. If you would like to analyze a core dump, you must run the -S argument (to disable strace) and also provide the -d argument. " 1
fi

if [ ! -f "testharness/Dockerfile.$tag" ]; then
  print_usage "Error - Invalid tag $tag specified" 1
fi

# Use the override Docker compose file too if it exists
if [ -e docker-compose.override.yml ]; then
  f+=(-f docker-compose.override.yml)
fi

# Perform various tests upon the supplied command with its arguments
$docker_compose "${f[@]}" build --build-arg "pspy_version=$(cd testharness/pspy && git describe --tags --always || echo unknown)" --build-arg "pspy_commit=$(cd testharness/pspy && git rev-parse HEAD || echo unknown)"
$docker_compose "${f[@]}" up -d listeningpost
containername="silentsentinel-testharness-run-$(od -vN 6 -An -tx1 /dev/urandom | tr -d ' \n')"
$docker_compose "${f[@]}" run --name "$containername" testharness "${tool_under_test_plus_args[@]}"
docker diff "$containername" > "$volpath/testharness/dockerdiff.out" 2>"$volpath/testharness/dockerdiff.err"
docker container rm "$containername"
$docker_compose "${f[@]}" stop listeningpost
$docker_compose "${f[@]}" run --rm yaf

# Run the Suricata container unless the user disables it
if [ "$suricata_enabled" -ne 0 ]; then
  $docker_compose "${f[@]}" run --rm suricata
fi

# Aggregate results into the desired report format(s)
case $report_generation in
  m|a)
    # Bind mount a JSON config file if one is provided
    if [ -n "$config_file_path" ]; then
      $docker_compose "${f[@]}" run --rm -v "$config_file_path:/config.json:ro" reportgeneration "${silent_sentinel_command_flags[@]}" "${tool_under_test_plus_args[@]}"
    else
      $docker_compose "${f[@]}" run --rm reportgeneration "${silent_sentinel_command_flags[@]}" "${tool_under_test_plus_args[@]}"
    fi
    ;;&
  a)
    $docker_compose "${f[@]}" run --rm pandoc
    ;;
esac
$docker_compose "${f[@]}" down

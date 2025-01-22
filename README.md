<legal>  
Silent Sentinel  
  
Copyright 2024 Carnegie Mellon University.  
  
NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING  
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON  
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS  
TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE  
OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.  
CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT  
TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.  
  
Licensed under a MIT (SEI)-style license, please see LICENSE.txt or contact  
permission@sei.cmu.edu for full terms.  
  
[DISTRIBUTION STATEMENT A] This material has been approved for public release  
and unlimited distribution.  Please see Copyright notice for non-US Government  
use and distribution.  
  
This Software includes and/or makes use of Third-Party Software each subject  
to its own license.  
  
DM24-1586  
</legal>  

![Logo](logo.svg)

# Silent Sentinel

Silent Sentinel is a command-line based utility that serves as a test bed for various computer programs. This is intended to run only on Linux hosts. Other systems (e.g., Docker Desktop on Mac) are not supported.

## Initialization of Repository
In order to correctly build the Silent Sentinel tool from source the pspy git submodule must be correctly configured. This happens automatically if this repository was cloned with the `--recursive` flag. If it wasn't, then it can be done by running the following command:

`$ git submodule update --init --recursive`

## Dependencies

Before running Silent Sentinel or its unit tests, you must install the following dependencies:

* Docker, version 20.10.5 or newer
* Docker Compose V2 plugin, version 2.24.6 or newer
* jq, version 1.6 or newer (only required to use the -c option)
* python3, version 3.6.8 or newer (only required for running automated tests)

Older versions may work but are neither tested nor supported.

## Running Silent Sentinel

Use the `-h` option to show the comprehensive usage documentation.

```bash
./silentsentinel.sh [-h] | [-c path/to/config.json] | [-C] [-P] [-S] [-U] [-d] [-r n/m/a] [-t TAG] <VOLUME_MOUNT_DIRECTORY> <TOOL_UNDER_TEST>
-c: Specify path to config.json file containing all Silent Sentinel settings
-C: Disable clamscan
-P: Disable PSPY
-S: Disable STRACE
-U: Disable Suricata
-d: Enable analyzing string data from a core dump
-r: Generate specified report formats: n - no report, m - markdown report, or a - all reports (default, markdown and pdf)
-t: Run instrumentation in specified tag of the testharness and listeningpost images during runtime (default: debian)
-h: Show usage documentation

To run strings analysis, create a file called 'wordlist' in the directory being mounted. (One search term per line in the file)
```

The command under test can be any executable. This executable must be present in the testharness container or in the volume mounted directory.
If desired, provide any command line arguments you would like to run with the command under test as well. Below are some examples of how to invoke Silent Sentinel with a command under test. `data_dir` is a local directory, whose contents are accessible inside the test containers as the `/vol` directory.

### **Example 1**: Running a command that is on the `$PATH` variable of the container environment.

`$ ./silentsentinel.sh ./data_dir bash -c 'ls -al'`

### **Example 2**: Running a custom Bash script that lives in the data_dir folder. This becomes a volume mounted directory of the container environment.

`$ ./silentsentinel.sh ./data_dir /vol/myScript.sh arg1 arg2`

### Volume Mounted Directory

The volume mounted directory argument allows Silent Sentinel to run the command under test inside a Docker container. Silent Sentinel also reads any input configuration files (i.e. the string analysis wordlist file). All output artifacts are written to this directory, such as the Markdown and PDF reports.

### Tags

Silent Sentinel supports multiple tags for the listeningpost and testharness container images, allowing the tool under test to be tested on different Linux distros. The following tags are available:

* `debian` (default)
* `fedora`
* `rockylinux`
* `ubuntu`
* `alpine`
* `archlinux` (only on amd64)

#### Troubleshooting

If you get errors like `Error - Invalid tag XXXXXXXX specified`, this means that you chose a tag that's not supported by Silent Sentinel at all.

If you get errors like `failed to resolve source metadata for XXXXXXXX: no match for platform in manifest: not found`, this means that you chose a tag that's not supported on your architecture (e.g., `archlinux` only supports amd64).

### Monitor System Processes

Silent Sentinel leverages pspy, which is a command line tool designed to snoop on processes without the need for root permissions. pspy detects when a process interacts with files such as libraries in `/usr`, temporary files in `/tmp`, log files in `/var`, etc. The inotify API provides notifications when a file is created, accessed, modified, or deleted. Privileged user access isn't required for this API, since this is needed for many basic applications (like a text editor). Non-root users cannot directly monitor other users' processes, but can monitor the _effects_ of them on the file system.

This tool can be very useful to see commands run by various users, cron jobs, etc. when they execute. The [pspy](https://github.com/DominicBreuker/pspy) GitHub page provides a more in-depth overview on this tool. The project maintainer states the following disclaimer about pspy:

> We can use the file system events as a trigger to scan /proc, hoping that we can do it fast enough to catch the processes. This is what pspy does. There is no guarantee you won't miss one, but chances seem to be good in my experiments. In general, the longer the processes run, the bigger the chance of catching them is.

By default, pspy is enabled when running `silentsentinel.sh`. If  you don't care about its output and want to save several seconds of startup time, you can skip running it by adding the `-P` command flag to the script.

### Strings Analysis

#### On the Tool Under Test

It can be useful to analyze the human-readable text in binary files. To run strings analysis, create a file called "_wordlist_" in the volume mounted directory. This _wordlist_ file shall contain one search term per line. The Silent Sentinel strings analysis will report on any strings in the binary file that match search terms in the _wordlist_ file. Strings analysis will not be performed if there is no _wordlist_ file in the volume mounted directory.

#### On Core Dumps

Silent Sentinel also has the ability to attach to the running tool under test's process, generate a core dump, and perform strings analysis. Selecting the `-d` option will generate a core dump of the tool under test without killing its process. This can be beneficial to view unencrypted data about the tool under test, including any data from network traffic. A tool under test may be a compiled binary or encrypted, so this can provide another avenue to learn more about the application.

**Note**: A core dump cannot be created when strace is running. gdb and strace can interfere with each other, so they are mutually exclusive settings. If you would like to generate strace output, omit `-d` (no core dump is produced). `strace` is activated by default. If you would like to analyze a core dump, you must run the `-S` argument (to disable `strace`) and also provide the `-d` argument. Please view the [Running the Oneshots](#running-the-oneshots) section for some examples on creating core dumps.

### Running the Oneshots

The oneshots provide a way to create a snapshot of resource utilization, core dumps, and more when it is run. In normal Silent Sentinel execution, the oneshots are run before the tool under test runs and after it finishes. There are some circumstances where an end user may want to run this script during the execution of the tool under test.

This README will show a few examples for controlling when the oneshots are run, but this is not an exhaustive list.

#### **Example 1**: Interactively issuing a oneshots command with `docker exec`
One approach can be to manually trigger the oneshots. To do this, you can open a separate terminal window. The basic concept is to wait for your tool under test to be actively running. Once it is running, fire a `docker exec` command into the testharness container from the alternate terminal. It is up to your discretion to choose when and how many times to run `docker exec` against the testharness container. You must know when the tool under test is actively running and at what point you might have interesting data.

Your `docker exec` command could look something like this, finding the ID of your container running the tool under test:

```
$ docker exec "$(docker ps --format '{{.ID}}' --filter 'name=testharness')" sh -c 'echo go > /run/oneshots_trigger; cat /run/oneshots_complete > /dev/null'
```

#### **Example 2**: Including oneshots triggers inside the tool under test
Another approach can be to programmatically trigger the oneshots exactly when desired. This can be accomplished by creating an executable script that is passed into the testharness container as the tool under test. Let's say we create a script called `tool_under_test.sh`. Inside this script, we add the following:

```sh
#!/bin/sh
# Ensure that your tool under test commands are running before triggering a core dump
scottish_graffiti=mac
export scottish_graffiti="${scottish_graffiti}beth was here"

# Trigger the oneshots
echo go > /run/oneshots_trigger
cat /run/oneshots_complete > /dev/null

# Run any commands after invoking a core dump
echo $scottish_graffiti
```

Then you would pass `tool_under_test.sh` into `silentsentinel.sh` like this. `tool_under_test.sh` will run from inside the volume mounted directory:

```
$ ./silentsentinel.sh -S -d ./data_dir /vol/tool_under_test.sh
```

#### **Example 3**: Invoking oneshots triggers via `openssh`
This approach supports use cases when `openssh` is the tool under test. You can trigger the oneshots by establishing an SSH connection to an `openssh` server and sending the relevant commands. You can use either an interactive or non-interactive SSH session to trigger the oneshots when desired.

### Report Generation

Silent Sentinel can generate reports in Markdown and PDF formats. If a PDF report is not required, such as during development, use the -r m option to only generate the Markdown report.

## Interpreting the Results

Silent Sentinel includes an Interpretation Guide that describes the tools and methods used to collect the data in the report and is intended to help reviewers of the data interpret the information.

The `pandoc` container which builds the Silent Sentinel report can be used to generate a PDF of the Interpretation Guide. Use the following command after the container images have been built, where the mounted volume contains the path to the Silent Sentinel repository:

```
docker run --rm -v "$(pwd)/doc:/vol" cmusei/silentsentinel-pandoc -i
```

The PDF will be generated in `doc` directory in the repository.

## Integration Testing

In order to run the Python-based automated tests, navigate to the root directory of this repository. Once there, run this command to invoke all integration tests:

`$ python3 -m unittest`

By default, the tests will run for all tags that Silent Sentinel supports on your system's architecture. You can set the `TAGS_TO_TEST` environment variable to a comma-separated list of tags to override this. For example, run this command to only test against the `debian` and `alpine` tags:

`$ TAGS_TO_TEST=debian,alpine python3 -m unittest`

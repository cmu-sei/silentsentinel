<legal>
Silent Sentinel

Copyright 2025 Carnegie Mellon University.

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
and unlimited distribution. Please see Copyright notice for non-US Government
use and distribution.

This Software includes and/or makes use of Third-Party Software each subject
to its own license.

DM25-0550
</legal>

![Logo](logo.svg)

# Silent Sentinel

Silent Sentinel is a command-line based utility that serves as a test bed for various computer programs.

## System Requirements

Silent Sentinel is only supported and tested on Linux operating systems with these CPU architectures: x86_64 (amd64), ARM (aarch64), and POWER (ppc64le)[^1]. Other systems (e.g., macOS, Windows) are not currently supported.

Before running Silent Sentinel or its unit tests, you must install the following software dependencies:

* Docker, version 20.10.5 or newer (version 28.0.0 or newer to use the -6 option)
* Docker Compose V2 plugin, version 2.24.6 or newer
* jq, version 1.6 or newer (only required to use the -c option)
* python3, version 3.6.8 or newer (only required for running automated tests)

Older versions may work but are neither tested nor supported.

Silent Sentinel requires a minimum of 20 GB of disk space available to Docker.

[^1]: The netflow analysis capability is not currently available on the POWER architecture and will produce a non-fatal error during Silent Sentinel's execution.

## Initialization of Repository

Silent Sentinel requires `pspy`, an open source tool, to be included as a Git submodule. To initialize the submodule, run the following command:

```bash
git submodule update --init --recursive
```

Once initialized, the pspy code can be found under `testharness/pspy`.

## Running Silent Sentinel

Silent Sentinel is a command-line utility. It can be run by either providing the necessary command flags or by providing a JSON configuration file.

Silent Sentinel can be used to analyze the executable actions of various types of binaries including installations of DEB or RPM packages, execution of shell scripts or custom applications, and more. This document refers to the software being analyzed as the "tool under test". The tool under test must be present in the testharness container or in the volume-mounted directory. Provide any designated command line arguments you would like to run with the tool under test, as well.

Run `./silentsentinel.sh -h` to view the comprehensive usage documentation.

### Basic Configuration Options

#### Volume Mount Directory

The volume mount directory positional argument is required for Silent Sentinel to run the command under test inside a Docker container. Silent Sentinel reads input configuration files from this directory (i.e., the strings analysis `wordlist` and YARA `rules.yar` files) and writes all output artifacts to this directory.

#### Tags

Silent Sentinel supports multiple tags for the listeningpost and testharness container images, allowing the tool under test to be tested on different Linux distributions. The following tags are available:

* `debian` (default)
* `fedora`
* `rockylinux`
* `ubuntu`
* `alpine`
* `archlinux` (only on amd64)

##### Troubleshooting Tags

If you get errors like `Error - Invalid tag XXXXXXXX specified`, this means that you chose a tag that's not supported by Silent Sentinel at all.

If you get errors like `failed to resolve source metadata for XXXXXXXX: no match for platform in manifest: not found`, this means that you chose a tag that's not supported on your architecture (e.g., `archlinux` only supports amd64).

#### Report Generation

Silent Sentinel can generate reports in both Markdown and PDF formats. If a PDF report is not required, such as during development, use the `-r m` option to only generate the Markdown report.

### Execution Examples

Below are some examples that demonstrate how to invoke Silent Sentinel with the relevant options provided. There are equivalent examples for invoking Silent Sentinel with all command line options or with a comparable `config.json` file; to do so: 

1. Copy one of the example config.json files in the `examples` directory to a new file called `config.json`. 
2. Modify your new file with any desired options.
3. Run Silent Sentinel with the `-c` flag. 

For more details, please see the Silent Sentinel [Configuration File specification](doc/config-file-overview.md).

**NOTE**: In the examples below, `data_dir` is a directory on the host machine. Silent Sentinel mounts this directory as a volume, making the contents accessible inside all Silent Sentinel containers as the `/vol` directory.

#### **Example 1**: Running a Command That Is on the `$PATH` Variable of the Container Environment

This example displays a commonly available utility that is installed inside the testharness container. Fedora is chosen as the testharness Linux distribution instead of the default (Debian).

##### Command Line Only Approach

```bash
./silentsentinel.sh -t fedora ./data_dir sh -c 'ls -al'
```

##### Configuration File Approach

Here is the accompanying [config.json](examples/example-config1.json) file.

```bash
./silentsentinel.sh -c ./examples/example-config1.json
```

#### **Example 2**: Running a Custom Bash Script That Lives in the data_dir Folder

In this example, `data_dir` is mounted as a volume called `/vol`. The script invokes the tool under test from `/vol` inside the testharness container. Here is an example that you could use in this manner [example2.sh](examples/example2.sh).

##### Command Line Only Approach

```bash
cp ./examples/example2.sh data_dir # you can use our example script
./silentsentinel.sh ./data_dir /vol/example2.sh listeningpost
```

##### Configuration File Approach

Here is the accompanying [config.json](examples/example-config2.json) file.

```bash
cp ./examples/example2.sh data_dir # you can use our example script
./silentsentinel.sh -c ./examples/example-config2.json
```

#### **Example 3**: Compiling a Binary from Source Code That Lives in the data_dir Folder 

You can download and extract source code for a utility like [dos2unix](https://waterlan.home.xs4all.nl/dos2unix/). By compiling the binary in the testharness container, you can run it in the native testharness environment and gain insights.

The [example3.sh](examples/example3.sh) script assumes that the dos2unix tarball exists in the `data_dir` directory on your local machine, which you can get by using the following command: 

`curl https://waterlan.home.xs4all.nl/dos2unix/dos2unix-7.5.2.tar.gz -o data_dir/dos2unix-7.5.2.tar.gz`

Then, the script compiles and installs the `dos2unix` utility in the testharness container. Executing `dos2unix` changes the line ending format of the `dos_db1.txt` file and writes it to a new file called `newfile.txt`.

Silent Sentinel then runs antivirus and other static analysis scans on the new file.

##### Command Line Only Approach

```bash
cp ./examples/example3.sh data_dir # you can use our example script
./silentsentinel.sh -U -S -P -a /vol/newfile.txt ./data_dir /vol/example3.sh
```

##### Configuration File Approach

Here is the accompanying [config.json](examples/example-config3.json) file.

```bash
cp ./examples/example3.sh data_dir # you can use our example script
./silentsentinel.sh -c ./examples/example-config3.json
```

#### **Example 4**: Executing a Python Application That Lives in the data_dir Folder Using the Rocky Linux Distribution

To analyze the execution of a Python application, you must copy the application files to the data_dir folder on your local system and ensure that Python will be installed in the selected testharness container.

Silent Sentinel then runs various analysis scans and profiles the application as it executes.

##### Command Line Only Approach

```bash
cp /origin/test.py data_dir # copy the necessary application files from their origin to the directory that will be mounted as a volume in the containers
cp ./examples/Dockerfile.rockylinux.example4 testharness/Dockerfile.rockylinux # Modify the Dockerfile for Rocky Linux to include a line to install Python 3 or use our example Dockerfile
./silentsentinel.sh -t rockylinux ./data_dir python3 -c 'print(2+2)'
```

##### Configuration File Approach

Here is the accompanying [config.json](examples/example-config4.json) file.

```bash
cp /origin/test.py data_dir # copy the necessary application files from their origin to the directory that will be mounted as a volume in the containers
cp ./examples/Dockerfile.rockylinux.example4 testharness/Dockerfile.rockylinux # Modify the Dockerfile for Rocky Linux to include a line to install Python 3 or use our example Dockerfile
./silentsentinel.sh -c ./examples/example-config4.json
```

### Advanced Configuration Options

#### Monitor System Processes

Silent Sentinel leverages pspy, which is a command line tool designed to snoop on processes without the need for root permissions. pspy detects when a process interacts with files such as libraries in `/usr`, temporary files in `/tmp`, log files in `/var`, and so on. The inotify API provides notifications when a file is created, accessed, modified, or deleted. Privileged user access isn't required for this API, since it is needed for many basic applications (like a text editor). Non-root users cannot directly monitor other users' processes but can monitor their _effects_ on the file system.

This tool can be very useful to see commands (run by various users, cron jobs, etc.) when they execute. The [pspy](https://github.com/DominicBreuker/pspy) GitHub page provides a more in-depth overview of this tool. The project maintainer states the following disclaimer about pspy:

> We can use the file system events as a trigger to scan /proc, hoping that we can do it fast enough to catch the processes. This is what pspy does. There is no guarantee you won't miss one, but chances seem to be good in my experiments. In general, the longer the processes run, the bigger the chance of catching them is.

By default, pspy is enabled when running `silentsentinel.sh`. If you do not care about its output and want to save several seconds of startup time, you can disable pspy by adding the `-P` command flag to the script.

#### Strings Analysis

It can be useful to analyze the human-readable text in binary files. To run strings analysis, create a file called `wordlist` in the volume mounted directory. This `wordlist` file must contain one search term per line. Strings analysis will not be performed if there is no `wordlist` file in the volume mounted directory.

##### On the Tool Under Test

By default, the Silent Sentinel strings analysis will report on any strings in the tool under test file that match search terms in the `wordlist` file. To learn how to override where the strings analysis is performed, please refer to the [Overriding Analysis Target Locations](#overriding-analysis-target-locations) section.

##### On Core Dumps

Silent Sentinel also has the ability to attach to the running tool under test's process, generate a core dump, and perform strings analysis. Selecting the `-d` option will generate a core dump of the tool under test without killing its process. This can be beneficial as it enables you to view unencrypted data about the tool under test, including any data from network traffic. A tool under test may be a compiled binary or encrypted, so this can provide another avenue to learn more about the application.

**Note**: A core dump cannot be created when strace is running. gdb and strace cannot both be attached to the same process at the same time, so they are mutually exclusive settings. If you would like to generate strace output, omit `-d` (no core dump is produced). `strace` is activated by default. If you would like to analyze a core dump, you must run the `-S` argument (to disable `strace`) and also provide the `-d` argument. Please view the [Running the Oneshots](#running-the-oneshots) section for some examples on creating core dumps.

#### Yara Rule Matching

Silent Sentinel uses [YARA](https://yara.readthedocs.io/en/stable/index.html) (Yet Another Ridiculous Acronym) to detect text or binary patterns in target files.

To run YARA, create a file called `rules.yar` in the volume mounted directory. YARA will not be used to analyze the tool under test if no `rules.yar` file is provided.

Additional rules files can be included by

* copying the rules files into the volume mounted directory
* specifying the `include` directive in the `rules.yar` file (e.g., `include "other-rules.yar"`)

Please read the YARA rules [documentation here](https://yara.readthedocs.io/en/stable/writingrules.html) to understand the expected syntax of the rules file.

#### Running the Oneshots

Oneshots provide a way to capture resource utilization, core dumps, and more at points in time during the tool under test’s execution. In a typical Silent Sentinel execution, the oneshots are run both before the tool under test runs and after it finishes. There are some circumstances where you may also want to collect oneshot instrumentation data during the execution of the tool under test.

This README will show a few examples for controlling when the oneshots are run, but this is not an exhaustive list.

##### **Example 5**: Interactively Issuing a Oneshots Command with `docker exec`

One approach is to manually trigger the oneshots via a separate terminal window when your tool under test is actively running. For this to be successful, you must know when the tool under test is actively running and at what point you might have interesting data. 

Once the tool under test is running, fire a `docker exec` command into the testharness container from the alternate terminal. You can choose when and how many times to run `docker exec` against the testharness container. 

Your `docker exec` command could look something like the following example, finding the ID of your container running the tool under test:

```bash
docker exec "$(docker ps --format '{{.ID}}' --filter 'name=testharness')" sh -c 'echo go > /run/oneshots_trigger; cat /run/oneshots_complete > /dev/null'
```

##### **Example 6**: Including Oneshots Triggers Inside the Tool Under Test

Another approach is to programmatically trigger the oneshots exactly when desired. To do so, write an executable script that is passed into the testharness container as the tool under test. For example, create a script called `invoke_oneshots.sh`. Inside this script, add the following:

[invoke_oneshots.sh](examples/invoke_oneshots.sh)

`invoke_oneshots.sh` will run from inside the volume mounted directory.

###### Command Line Only Approach

Pass `invoke_oneshots.sh` into `silentsentinel.sh` like the following:

```bash
cp ./examples/invoke_oneshots.sh data_dir # you can use our example script
./silentsentinel.sh -S -d ./data_dir /vol/invoke_oneshots.sh
```

###### Configuration File Approach

Pass `invoke_oneshots.sh` into `silentsentinel.sh` like the following:

```bash
cp ./examples/invoke_oneshots.sh data_dir # you can use our example script
cp ./examples/invoke-oneshots-example-config.json ./config.json
./silentsentinel.sh -c ./config.json
```

Here is the accompanying [config.json](examples/invoke-oneshots-example-config.json) file.

##### **Example 7**: Invoking Oneshots Triggers via `openssh`

This approach supports use cases when `openssh` is the tool under test. You can trigger the oneshots by establishing an SSH connection to an `openssh` server and sending the relevant commands. You can use either an interactive or non-interactive SSH session to trigger the oneshots when desired.

If your listeningpost container has an `ssh` binary in it, you could do this (from another terminal while Silent Sentinel is already running the tool under test):

```bash
volpath=/nonexistent-dummy tag=debian docker compose exec listeningpost ssh testharness
```

Or if the tool is on the host system, you can use it from the listeningpost container's network namespace like this:

```bash
sudo nsenter --net=$(docker inspect "$(volpath=/nonexistent-dummy tag=debian docker compose ps listeningpost --format '{{ .ID }}')" --format '{{ .NetworkSettings.SandboxKey }}') ssh testharness
```

#### Overriding Analysis Target Locations

By default, Silent Sentinel performs various static analysis techniques on the first argument of the tool under test. (Examples are clamscanAV, strings, etc.) This might not always be useful, since the tool under test could be a wrapper script. However, the analyst can override this default behavior. Silent Sentinel can instead be directed to recursively scan any number of provided files/directories instead of the tool under test.

Select the files and/or directories to target analysis either by using command line arguments or a configuration .json file. Note that any file or directory that does not exist will be skipped. Silent Sentinel will just print a warning message.

Here is an example of the relevant section to add to the top-level of your configuration .json file:

```json
"analysisToolTargets": [
    "/vol/test-dir",
    "/vol/test-file"
],
```

Here is the equivalent way to override the default string location with command line options:

```bash
silentsentinel.sh -a /vol/test-dir -a /vol/test-file VOLUME_MOUNT_DIRECTORY TOOL_UNDER_TEST
```

#### Measuring Disk I/O

Silent Sentinel measures the amount of data read from and written to the hard drives. To isolate your tool under test's disk activity, Silent Sentinel uses data from `cgroups`. A dedicated cgroup is created for the testharness container, which tracks I/O operations exclusively for the tool under test. No other containers or host operating system processes are totaled. Note that this feature only works if the host operating system uses `cgroups` version 2. If the host operating system uses `cgroups` version 1, disk I/O will be omitted from generated reports.

#### Custom Instrumentation

In addition to its built-in instrumentation, Silent Sentinel allows the user to specify custom instrumentation to run.

##### Custom Static Analysis and Continuous Tools

Create a script named `custom_startup.sh` in the volume mounted directory. This script will be sourced by Silent Sentinel's entrypoint script in the testharness container before the tool under test starts. Run static analysis tools like the following:

```sh
MY_CUSTOM_STATIC_ANALYSIS_TOOL > /vol/testharness/MY_CUSTOM_STATIC_ANALYSIS_TOOL.out 2>/vol/testharness/MY_CUSTOM_STATIC_ANALYSIS_TOOL.err
```

Run continuous tools like the following:

```sh
MY_CUSTOM_CONTINUOUS_TOOL > /vol/testharness/MY_CUSTOM_CONTINUOUS_TOOL.out 2>/vol/testharness/MY_CUSTOM_CONTINUOUS_TOOL.err &
MY_CUSTOM_CONTINUOUS_TOOL_pid=$!
```

If you are only using custom static analysis tools, the above is sufficient. If you are also using custom continuous tools, you must create a script named `custom_shutdown.sh` in the volume mounted directory. This script will be sourced by Silent Sentinel's entrypoint script in the testharness container after the tool under test exits. Stop continuous tools like the following:

```sh
kill "$MY_CUSTOM_CONTINUOUS_TOOL_pid"
wait "$MY_CUSTOM_CONTINUOUS_TOOL_pid"
```

If your custom continuous tool does not reliably respond to SIGTERM, the above can be modified to get it to exit by whatever means are appropriate.

##### Custom Oneshot Tools

Create a directory named `custom_oneshots` in the volume mounted directory. Every executable file in that subdirectory will be run by Silent Sentinel's oneshots script in the testharness container every time the oneshots are executed, and the resulting standard output and standard errors will automatically be captured with diffs added to the report.

### Report Generation

Silent Sentinel can generate reports in both Markdown and PDF formats. If a PDF report is not required, such as during development, use the `-r m` option to only generate the Markdown report.

## Interpreting the Results

Silent Sentinel includes an Interpretation Guide that describes the tools and methods used to collect the data in the report and helps reviewers of the data interpret the information. The Markdown contents of the Interpretation Guide can be found [here](doc/interpretation-guide.md).

The `pandoc` container, which builds the Silent Sentinel report, can be used to generate a PDF of the Interpretation Guide. Use the following command after the container images have been built, where the mounted volume contains the path to the Silent Sentinel repository:

```bash
docker run --rm -v "$(pwd)/doc:/vol" cmusei/silentsentinel-pandoc -i
```

The PDF will be generated in the `doc` directory of the repository.

## Integration Testing

To run the Python-based automated tests, navigate to the root directory of the repository. Once there, run the following command to invoke all integration tests:

`python3 -m unittest`

By default, the tests will run for all tags that Silent Sentinel supports on your system's architecture. You can set the `TAGS_TO_TEST` environment variable to a comma-separated list of tags to override this. For example, run the following command to only test against the `debian` and `alpine` tags:

`TAGS_TO_TEST=debian,alpine python3 -m unittest`

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

import json
import os
import platform
import re
import shutil
import tempfile
import unittest
from functools import wraps
from subprocess import run, PIPE
from glob import glob

try:
    tagsToTest = os.environ['TAGS_TO_TEST'].split(',')
except KeyError:
    tagsToTest = ['debian', 'alpine', 'ubuntu', 'fedora', 'rockylinux']
    if platform.machine() == 'x86_64':
        tagsToTest.append('archlinux')

def subTestTags(f):
    """
    To ensure that all parts of Silent Sentinel work on all distros, this
    decorator wraps unit tests in a loop that runs them once for each of
    our tags, with each run in its own subtest and with its own subdirectory
    for self.tmp_folder_loc.
    """
    @wraps(f)
    def wrapper(self):
        tmp_folder_loc = self.tmp_folder_loc
        try:
            for tag in tagsToTest:
                with self.subTest(tag=tag):
                    self.tmp_folder_loc = os.path.join(tmp_folder_loc, tag)
                    os.mkdir(self.tmp_folder_loc)
                    f(self, tag)
        finally:
            self.tmp_folder_loc = tmp_folder_loc
    return wrapper

class SilentSentinelTest(unittest.TestCase):
    """
    This class serves as a test fixture for automated integration testing
    of Silent Sentinel. In each test, Silent Sentinel is invoked with a series
    of command line arguments. This tests the integration of the test harness,
    report generation, etc. instead of testing each component in isolation.
    """

    # Create temp folder for test case
    def setUp(self) -> None:
        self.tmp_folder_loc = tempfile.mkdtemp(dir=os.getcwd())

    # Delete folder after test case is complete
    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_folder_loc)

    # Return a set containing the headers within the report file
    def get_headers_list(self) -> set:
        headers_list = set()
        for file in os.listdir(self.tmp_folder_loc):
            if file.endswith('.md'):
                with open(os.path.join(self.tmp_folder_loc, file), 'r') as md_file:
                    for line in md_file.readlines():
                        if line.startswith('## ') and line.endswith(' \n'):
                            headers_list.add(line[3:-2])
        return headers_list

    def markdown_report_contains_string(self, regex_pattern) -> bool:
        """
        Return True if a provided string or regex pattern is found
        in the Markdown report, False otherwise.
        """

        # Retrieve the most recently created Markdown report to search
        markdown_report_files = sorted(glob(os.path.join(self.tmp_folder_loc, "*.md")))
        if not markdown_report_files:
            return False

        markdown_report_filepath = markdown_report_files[-1]

        # Open the Markdown report and search for the regex pattern
        with open(markdown_report_filepath, 'r') as markdown_report:
            for line in markdown_report:
                if re.search(regex_pattern, line):
                    return True

        return False

    def test_usage_message(self):
        session = run(['./silentsentinel.sh'], stdout=PIPE)
        self.assertTrue(b'arguments are missing' in session.stdout, "Testing that correct error message appears for illegal usage")
        sessionTwo = run(['./silentsentinel.sh', '-h'], stdout=PIPE)
        self.assertTrue(b'Silent Sentinel Usage' in sessionTwo.stdout, "Testing that the usage message appears when -h is used")

        env = {**os.environ, 'PATH': self.tmp_folder_loc + ':' + os.environ['PATH']}

        with os.fdopen(os.open(os.path.join(self.tmp_folder_loc, "docker"), os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o777), "w") as f:
            f.write("#!/bin/sh\nexport PATH=${PATH#*:}\nif [ \"$1\" = version ]; then exit 1; fi; exec docker \"$@\"")
        sessionThree = run(['./silentsentinel.sh', '-h'], stdout=PIPE, env=env)
        self.assertTrue(b"docker version' command failed" in sessionThree.stdout, "Testing that docker version failing is reported to the user")
        self.assertNotEqual(sessionThree.returncode, 0, "Testing that docker version failing causes Silent Sentinel to fail")

        with os.fdopen(os.open(os.path.join(self.tmp_folder_loc, "docker"), os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o777), "w") as f:
            f.write("#!/bin/sh\nexport PATH=${PATH#*:}\nif [ \"$1\" = compose ]; then exit 1; fi; exec docker \"$@\"")
        sessionFour = run(['./silentsentinel.sh', '-h'], stdout=PIPE, env=env)
        self.assertTrue(b"compose version' command failed" in sessionFour.stdout, "Testing that docker compose version failing is reported to the user")
        self.assertNotEqual(sessionFour.returncode, 0, "Testing that docker compose version failing causes Silent Sentinel to fail")

    # Testing all tools that will produce output when ping is run in the container
    @subTestTags
    def test_ping_output(self, tag):
        session = run(['./silentsentinel.sh', '-t', tag, '-P', '-C', '-U', '-r', 'm', self.tmp_folder_loc, 'ping', '-c', '1', '-w', '2', 'listeningpost'])
        self.assertEqual(session.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        report_headers_list = self.get_headers_list()
        testharness_loc = os.path.join(self.tmp_folder_loc, 'testharness')
        listeningpost_loc = os.path.join(self.tmp_folder_loc, 'listeningpost')

        # Test that PCAP data is being generated for testharness and listeningpost
        self.assertIn('tcpdump.err', os.listdir(testharness_loc),
                      "Testing no errors thrown in tcpdump")
        self.assertIn('tcpdump.pcap', os.listdir(testharness_loc),
                      "Testing testharness tcpdump pcap file creation")
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, 'tcpdump.pcap')).st_size, 0,
                            "Testing that testharness pcap file has data in it")
        self.assertIn('tcpdump.pcap', os.listdir(listeningpost_loc),
                      'Testing that listeningpost-tcpdump pcap file is created')
        self.assertNotEqual(os.stat(os.path.join(listeningpost_loc, 'tcpdump.pcap')).st_size, 0,
                            "Testing that listeningpost pcap file has data in it")

        # Test that yaf and fixbuf are correctly ingesting and creating files
        self.assertIn('pcap.ipfix', os.listdir(listeningpost_loc),
                      'Testing that ipfix file is created for listeningpost')
        self.assertIn('pcap.ipfix', os.listdir(testharness_loc),
                      'Testing that ipfix file is created for testharness')
        self.assertNotEqual(os.stat(os.path.join(listeningpost_loc, "pcap.ipfix")).st_size, 0,
                            'Confirming that data is being written to ipfix file for listeningpost')
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, "pcap.ipfix")).st_size, 0,
                            'Confirming that data is being written to ipfix file for testharness')

        # Checking that non-APPLABEL/DPI ipfix file is created and written to
        self.assertIn('simple_pcap.ipfix', os.listdir(listeningpost_loc),
                      'Testing that simple ipfix file is created for listeningpost')
        self.assertIn('simple_pcap.ipfix', os.listdir(testharness_loc),
                      'Testing that simple ipfix file is created for testharness')
        self.assertNotEqual(os.stat(os.path.join(listeningpost_loc, "simple_pcap.ipfix")).st_size, 0,
                            'Confirming that data is being written to simple ipfix file for listeningpost')
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, "simple_pcap.ipfix")).st_size, 0,
                            'Confirming that data is being written to simple ipfix file for testharness')

        # Check that pcap json file is created
        self.assertIn('pcap.json', os.listdir(listeningpost_loc),
                      "Testing that listeningpost pcap json file is created")
        self.assertIn('pcap.json', os.listdir(testharness_loc),
                      "Testing that testharness pcap json file is created")
        self.assertNotEqual(os.stat(os.path.join(listeningpost_loc, "pcap.json")).st_size, 0,
                            'Confirming that data is being written to pcap json file for listeningpost')
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, "pcap.json")).st_size, 0,
                            'Confirming that data is being written to pcap json file for testharness')

        # Test that suricata was disabled
        self.assertNotIn('raw-suricata-events.log', os.listdir(testharness_loc),
                         'Testing that the raw-suricata-events file is not created')
        self.assertNotIn('suricata-statistics.out', os.listdir(testharness_loc),
                         'Testing that suricata statistics file is not created')
        self.assertNotIn('suricata.err', os.listdir(testharness_loc),
                         'Testing that suricata errors file is not created')

        # Verify that the Suricata sections with their headers don't appear in the Markdown report
        self.assertNotIn("suricata-events", report_headers_list)
        self.assertNotIn("suricata-statistics", report_headers_list)

        # Test that YARA was not run, due to no rules.yar file being present
        self.assertIn('yara-rule-matches.out', os.listdir(testharness_loc),
                      'Testing that the YARA output file is created')
        with open(os.path.join(testharness_loc, 'yara-rule-matches.out'), 'r') as yara_matches_output_file:
            match_file_contents = yara_matches_output_file.read()
            match_file_contents = match_file_contents.strip()
            self.assertEqual('YARA was not run.', match_file_contents, 'Unexpected contents in yara-rule-matches.out')

        # Verify that the YARA section with its header doesn't appear in the Markdown report
        self.assertIn("yara-rule-matches", report_headers_list)

        # Check that flows ascii file is created
        self.assertIn("netflow", report_headers_list)
        self.assertIn('netflow.out', os.listdir(listeningpost_loc),
                      'Testing that ipfix file is created for listeningpost')
        self.assertIn('netflow.out', os.listdir(testharness_loc),
                      'Testing that ipfix file is created for testharness')
        self.assertNotEqual(os.stat(os.path.join(listeningpost_loc, "netflow.out")).st_size, 0,
                            'Confirming that data is being written to ipfix file for listeningpost')
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, "netflow.out")).st_size, 0,
                            'Confirming that data is being written to ipfix file for testharness')

        # Test that strings outputs correctly
        self.assertIn('strings.out', os.listdir(testharness_loc), "Testing that strings.out is in output folder")
        self.assertIn('strings.err', os.listdir(testharness_loc), "Testing that strings.err is in output folder")
        with open(os.path.join(testharness_loc, 'strings.out'), "r") as stringsoutfile:
            self.assertIn('not run', stringsoutfile.read(), "Testing that strings.out had the not run heading")
        self.assertEqual(os.stat(os.path.join(testharness_loc, "strings.err")).st_size, 0,
                         "Testing that no error is thrown to strings.err")

        # Test that the network bandwidth section outputs correctly, including its embedded image file
        embedded_image_regex_pattern = r"!\[.*\]\(\w+/network-bandwidth-graph\.png\)"
        self.assertIn("network-bandwidth-graph", report_headers_list)
        self.assertIn("network-bandwidth-graph.png", os.listdir(testharness_loc),
                      'Network bandwidth graph image file is not created in testharness subdirectory')
        self.assertTrue(self.markdown_report_contains_string(embedded_image_regex_pattern), 'Markdown report does not contain embedded image')

        # Test that the disk I/O performance section outputs correctly, including its embedded image file
        embedded_image_regex_pattern = r"!\[.*\]\(\w+/disk-performance-graph\.png\)"
        self.assertIn("disk-performance-graph", report_headers_list)
        self.assertIn("disk-performance-graph.png", os.listdir(testharness_loc),
                      'Disk I/O performance graph image file is not created in testharness subdirectory')
        self.assertTrue(self.markdown_report_contains_string(embedded_image_regex_pattern), 'Markdown report does not contain embedded image')

        # Test that PANDOC was disabled
        self.assertFalse(glob(os.path.join(self.tmp_folder_loc, '*.pdf')),
                            'Confirming that the pdf file is not created by pandoc')

    # Only testing Suricata and Pandoc on a single tag, since they're very slow and are unaffected by the choice of tag due to being in different containers
    def test_non_tag_tools(self):
        session = run(['./silentsentinel.sh', '-P', '-C', self.tmp_folder_loc, 'ping', '-c', '1', '-w', '2', 'listeningpost'])
        self.assertEqual(session.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        report_headers_list = self.get_headers_list()
        testharness_loc = os.path.join(self.tmp_folder_loc, 'testharness')

        # Test that suricata is correctly creating files
        self.assertIn('raw-suricata-events.log', os.listdir(testharness_loc),
                      'Testing that the raw-suricata-events file is created')
        self.assertIn('suricata-statistics.out', os.listdir(testharness_loc),
                      'Testing that suricata statistics file is created')
        self.assertIn('suricata.err', os.listdir(testharness_loc),
                      'Testing that suricata errors file is created')
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, "raw-suricata-events.log")).st_size, 0,
                            'Confirming that data is being written to the suricata events file')
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, "suricata-statistics.out")).st_size, 0,
                            'Confirming that data is being written to the suricata statistics file')
        self.assertEqual(os.stat(os.path.join(testharness_loc, "suricata.err")).st_size, 0,
                            'Confirming that the suricata errors file is empty')

        # Verify that the expected Suricata sections with their headers appear in the Markdown report
        self.assertIn("suricata-events", report_headers_list)
        self.assertIn("suricata-statistics", report_headers_list)

        # Test that the PDF document is created by PANDOC
        self.assertTrue(glob(os.path.join(self.tmp_folder_loc, '*.pdf')),
                            'Confirming that the pdf file is created by pandoc')

    # Only test YARA on a single tag. This requires a custom tool under test that will
    # exist in the volume mounted directory. Runs in a separate container, so not needed to
    # run various tags.
    def test_non_tag_yara(self):
        # Create YARA rules file and custom tool under test
        yara_rule_contents = """import "pe"

rule String_Match
{
    meta:
        author = "Bugs Bunny"
        date = "2025-03-10"
        description = "Detects for any data exfiltration or tool installation patterns"
    strings:
        $Quarantine_Message1 = "install" nocase
        $Quarantine_Message2 = "upload" nocase
        $Prevent_Quarantine = "meeting"

    condition:
        ($Quarantine_Message1 or $Quarantine_Message2) and not $Prevent_Quarantine
}
"""
        yara_rule_file_path = os.path.join(self.tmp_folder_loc, "rules.yar")
        with open(yara_rule_file_path, "w") as yara_rule_file:
            yara_rule_file.write(yara_rule_contents)

        tool_under_test_contents = """#!/bin/bash

# This script is meant to intentionally trigger rules set in
# the rules.yar file.

echo "Let's install a time for our weekly scan"
echo "Try to install a foreign and untrusted package hahaha"
echo "Upload the results back to our homebase server"
"""
        tool_under_test = os.path.join(self.tmp_folder_loc, "trigger-yara.sh")
        with open(tool_under_test, "w") as tool_under_test:
            tool_under_test.write(tool_under_test_contents)
        os.chmod(tool_under_test.name, 0o555)

        session = run(['./silentsentinel.sh', '-S', '-P', '-C', '-U', '-r', 'm', self.tmp_folder_loc, '/vol/trigger-yara.sh'])
        self.assertEqual(session.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        report_headers_list = self.get_headers_list()
        testharness_loc = os.path.join(self.tmp_folder_loc, 'testharness')

        # Test that YARA was run; output file should contain expected first line
        self.assertIn('yara-rule-matches.out', os.listdir(testharness_loc),
                      'Testing that the YARA output file is created')
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, "yara-rule-matches.out")).st_size, 0,
                            'Confirming that the YARA output file is not empty')
        with open(os.path.join(testharness_loc, 'yara-rule-matches.out'), 'r') as yara_matches_output_file:
            match_file_contents = yara_matches_output_file.readline()
            match_file_contents = match_file_contents.strip()
            self.assertEqual('The YARA scan detected the following match(es) in the provided rules:',
                             match_file_contents,
                             'Unexpected contents in yara-rule-matches.out')

        # Verify that the YARA section with its header appears in the Markdown report
        self.assertIn("yara-rule-matches", report_headers_list)

    # Testing all tools that will produce output when iptables is run in the container
    @subTestTags
    def test_iptables_output(self, tag):
        session = run(['./silentsentinel.sh', '-t', tag, '-P', '-C', '-U', '-r', 'm', self.tmp_folder_loc, 'iptables', '-A', 'OUTPUT', '-j', 'ACCEPT'])
        self.assertEqual(session.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        report_headers_list = self.get_headers_list()
        testharness_loc = os.path.join(self.tmp_folder_loc, 'testharness')

        # Test that iptables outputs to correct files and with actual data
        print(os.path.join(testharness_loc, 'iptables'))
        self.assertTrue(glob(os.path.join(testharness_loc, 'iptables', '*.out')),
                        "Testing iptables file creation")
        self.assertTrue(glob(os.path.join(testharness_loc, 'iptables', '*.diff')),
                        "Testing iptables diff file creation")
        self.assertNotEqual(os.stat(glob(os.path.join(testharness_loc, 'iptables', '*.diff'))[0]).st_size, 0,
                            "Testing iptables outputs had differences")
        self.assertTrue(glob(os.path.join(testharness_loc, 'iptables', '*.err')),
                        "Testing iptables stderr file creation")
        self.assertIn("iptables", report_headers_list,
                      "Testing that iptables is in the report")

    # Confirm that no matching dirty words in the binary itself outputs correctly
    @subTestTags
    def test_no_matching_dirty_words(self, tag):
        with os.fdopen(os.open(os.path.join(self.tmp_folder_loc, "tool_under_test.sh"), os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o777), "w") as f:
            f.write("#!/bin/sh\nscottish_graffiti=mac\nexport scottish_graffiti=\"${scottish_graffiti}beth was here\"\necho go > /run/oneshots_trigger\ncat /run/oneshots_complete > /dev/null\necho $scottish_graffiti\n")
        with open(os.path.join(self.tmp_folder_loc, "wordlist"), "w") as f:
            f.write("juliet\nmacbeth\nhamlet\n")

        session = run(['./silentsentinel.sh', '-t', tag, '-P', '-C', '-U', '-S', '-d', '-r', 'n', self.tmp_folder_loc, '/vol/tool_under_test.sh'])
        self.assertEqual(session.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        testharness_loc = os.path.join(self.tmp_folder_loc, 'testharness')

        self.assertIn('strings.out', os.listdir(testharness_loc), "Testing that strings.out is in output folder")
        self.assertIn('strings.err', os.listdir(testharness_loc), "Testing that strings.err is in output folder")
        with open(os.path.join(testharness_loc, 'strings.out'), "r") as stringsoutfile:
            self.assertIn('did not detect', stringsoutfile.read(), "Testing that strings.out had the did not detect heading")
        self.assertEqual(os.stat(os.path.join(testharness_loc, "strings.err")).st_size, 0,
                         "Testing that no error is thrown to strings.err")

        coredump_data_directory = os.path.join(testharness_loc, 'coredump-strings')
        self.assertTrue(glob(os.path.join(coredump_data_directory, 'coredump-strings_*.out')), "Testing coredump strings out file creation")
        self.assertTrue(glob(os.path.join(coredump_data_directory, 'coredump-strings_*.err')), "Testing coredump strings err file creation")
        with open(glob(os.path.join(coredump_data_directory, 'coredump-strings_*.out'))[0], "r") as stringsoutfile:
            stringsoutcontent = stringsoutfile.read()
            self.assertIn('detected', stringsoutcontent, "Testing that the coredump strings out file had the detected heading")
            self.assertIn('macbeth was here', stringsoutcontent, "Testing that the coredump strings out file had the detected line")
        self.assertEqual(os.stat(glob(os.path.join(coredump_data_directory, 'coredump-strings_*.err'))[0]).st_size, 0, "Testing that no error is thrown to the coredump strings err file")


    # Confirm that no errors are thrown when attempting to start silentsentinel
    @subTestTags
    def test_start_success(self, tag):
        # Create an empty YARA rules file
        yara_rule_file_path = os.path.join(self.tmp_folder_loc, "rules.yar")
        open(yara_rule_file_path, "w").close()

        with os.fdopen(os.open(os.path.join(self.tmp_folder_loc, "tool_under_test.sh"), os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o777), "w") as f:
            f.write("#!/bin/sh\n# macbeth was here\necho hello\n")
        with open(os.path.join(self.tmp_folder_loc, "wordlist"), "w") as f:
            f.write("juliet\nmacbeth\nhamlet\n")

        session = run(['./silentsentinel.sh', '-t', tag, '-U', '-r', 'm', self.tmp_folder_loc, '/vol/tool_under_test.sh'], stdout=PIPE)
        self.assertEqual(session.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        # Check that silent sentinel ran simple command
        self.assertIn(b'hello', session.stdout.splitlines(), "Testing that Silent Sentinel ran successfully")

        report_headers_list = self.get_headers_list()
        testharness_loc = os.path.join(self.tmp_folder_loc, 'testharness')

        # Test that reading the contents of crontabs outputs to correct files
        self.assertTrue(glob(os.path.join(testharness_loc, 'crontabs', '*.diff')),
                        "Testing crontabs file creation")

        # Test that reading the contents of memory.stat outputs to correct files
        self.assertTrue(glob(os.path.join(testharness_loc, 'memory-stat', '*.out')),
                        "Testing memory.stat file creation")
        self.assertNotEqual(os.stat(glob(os.path.join(testharness_loc, 'memory-stat', '*.out'))[0]).st_size, 0,
                        "Testing memory.stat output to file")
        self.assertTrue(glob(os.path.join(testharness_loc, 'memory-stat', '*.err')),
                        "Testing memory.stat stderr file creation")
        self.assertEqual(os.stat(glob(os.path.join(testharness_loc, 'memory-stat', '*.err'))[0]).st_size, 0,
                        "Testing memory.stat output to error file")

        # Checking for strace json file
        self.assertIn('strace.json', os.listdir(testharness_loc),
                      'Testing that parsed strace file has been created')

        # Checking for files after ps tool is run
        self.assertNotEqual(os.stat(glob(os.path.join(testharness_loc, 'ps', '*_filtered.out'))[0]).st_size, 0,
                            "Testing filtered ps output to file")
        self.assertTrue(glob(os.path.join(testharness_loc, 'ps', '*.diff')),
                        "Testing ps diff file creation")
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, 'ps', 'ps_0.diff')).st_size, 0,
                            "Testing that the differences between ps files are recorded")
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, 'ps', 'ps_0.diff')).st_size, 0,
                            "Testing that the differences between ps files are recorded")
        self.assertIn('ps', report_headers_list,
                      "Testing that ps is in the report file")

        # Test that pspy outputs correctly
        self.assertIn('pspy.out', os.listdir(testharness_loc), "Testing that pspy.out is in output folder")
        self.assertIn('pspy.err', os.listdir(testharness_loc), "Testing that pspy.err is in output folder")
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, "pspy.out")).st_size, 0,
                            "Testing that output is written to pspy.out")
        self.assertEqual(os.stat(os.path.join(testharness_loc, "pspy.err")).st_size, 0,
                         "Testing that no error is thrown to pspy.err")

        # Test that clamscan outputs correctly
        self.assertIn('clamscan.out', os.listdir(testharness_loc), "Testing that clamscan.out is in output folder")
        self.assertIn('clamscan.err', os.listdir(testharness_loc), "Testing that clamscan.err is in output folder")
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, "clamscan.out")).st_size, 0,
                            "Testing that output is written to clamscan.out")
        self.assertEqual(os.stat(os.path.join(testharness_loc, "clamscan.err")).st_size, 0,
                         "Testing that no error is thrown to clamscan.err")

        # Test that strings outputs correctly
        self.assertIn('strings.out', os.listdir(testharness_loc), "Testing that strings.out is in output folder")
        self.assertIn('strings.err', os.listdir(testharness_loc), "Testing that strings.err is in output folder")
        with open(os.path.join(testharness_loc, 'strings.out'), "r") as stringsoutfile:
            stringsoutcontent = stringsoutfile.read()
            self.assertIn('detected', stringsoutcontent, "Testing that strings.out had the detected heading")
            self.assertIn('macbeth was here', stringsoutcontent, "Testing that strings.out had the detected line")
        self.assertEqual(os.stat(os.path.join(testharness_loc, "strings.err")).st_size, 0,
                         "Testing that no error is thrown to strings.err")

        # Test that YARA was run
        self.assertIn('yara-rule-matches.out', os.listdir(testharness_loc),
                      'Testing that the YARA output file is created')
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, "yara-rule-matches.out")).st_size, 0,
                            'Confirming that the YARA output file is not empty')
        with open(os.path.join(testharness_loc, 'yara-rule-matches.out'), 'r') as yara_matches_output_file:
            match_file_contents = yara_matches_output_file.read()
            match_file_contents = match_file_contents.strip()
            self.assertEqual('The YARA scan did not detect any matches in the provided rules.',
                             match_file_contents,
                             'Unexpected output in yara-rule-matches.out')

        # Verify that the YARA section with its header appears in the Markdown report
        self.assertIn("yara-rule-matches", report_headers_list)

    # Confirm that changes made to the crontab files are registered and placed in report generation file
    @subTestTags
    def test_crontab_changes(self, tag):
        session = run(['./silentsentinel.sh', '-t', tag, '-P', '-C', '-U', '-r', 'm', self.tmp_folder_loc, 'sh', '-c', 'echo "# test modification" >> /etc/crontab'])
        self.assertEqual(session.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        report_headers_list = self.get_headers_list()
        testharness_loc = os.path.join(self.tmp_folder_loc, 'testharness')
        self.assertTrue(glob(os.path.join(testharness_loc, 'crontabs', '*.diff')),
                        "Testing crontabs diff file creation")
        self.assertIn('crontabs', report_headers_list,
                      "Testing that crontab is in the report file")
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, 'crontabs', 'crontabs_0.diff')).st_size, 0,
                            "Testing that the differences between crontab files are recorded")

    # Verify that we can override the default analysis target (e.g. clamscan, strings, etc.)
    # No dirty words should be found on the tool under test, since we override to search
    # on other analysis target locations.
    def test_override_analysis_targets(self):
        # Create a test JSON config file and pass it to Silent Sentinel
        config_file_content = {
            "volumeMountDirectory": self.tmp_folder_loc,
            "toolUnderTest": [
                "sh",
                "-c",
                "echo \"The African Grey has a large vocabulary\""
            ],
            "tag": "debian",
            "analysisTools":
            {
                "clamscan": True,
                "coreDumps": False,
                "pspy": False,
                "strace": False,
                "suricata": False
            },
            "analysisToolTargets": [
                "/vol/extra-test-dir",
                "/vol/extra-test-file",
                "/vol/nonexisting-dir"
            ],
            "reportFormat": "markdown"
        }

        path_to_test_config_file = os.path.join(self.tmp_folder_loc, "test-config.json")
        with open(path_to_test_config_file, "w") as test_config_file:
            json.dump(config_file_content, test_config_file, indent=4)

        # Create a dirty words list and some test files with suspicious strings
        with open(os.path.join(self.tmp_folder_loc, "wordlist"), "w") as f:
            f.write("macaw\nAfrican Grey\ncockatoo\ncaique\n")

        with open(os.path.join(self.tmp_folder_loc, "extra-test-file"), "w") as f:
            f.write("The macaw flew the coop!")

        new_file_target_dir = os.path.join(self.tmp_folder_loc, "extra-test-dir")
        os.mkdir(new_file_target_dir)
        with open(os.path.join(new_file_target_dir, "file1"), "w") as f:
            f.write("mammal: mouse\nbird: cockatoo\nfish: shark\n")

        sessionExpectingSuccess = run(['./silentsentinel.sh', '-c', path_to_test_config_file])
        self.assertEqual(sessionExpectingSuccess.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        testharness_loc = os.path.join(self.tmp_folder_loc, 'testharness')
        report_headers_list = self.get_headers_list()

        # Test that clamscan outputs correctly
        self.assertIn('clamscan.out', os.listdir(testharness_loc), "Testing that clamscan.out is in output folder")
        self.assertIn('clamscan.err', os.listdir(testharness_loc), "Testing that clamscan.err is in output folder")
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, "clamscan.out")).st_size, 0,
                            "Testing that output is written to clamscan.out")
        self.assertEqual(os.stat(os.path.join(testharness_loc, "clamscan.err")).st_size, 0,
                         "Testing that no error is thrown to clamscan.err")
        self.assertIn('clamscan', report_headers_list, "Testing that clamscan is in the report file")

        # Test that strings outputs correctly
        self.assertIn('strings.out', os.listdir(testharness_loc), "Testing that strings.out is in output folder")
        self.assertIn('strings.err', os.listdir(testharness_loc), "Testing that strings.err is in output folder")
        with open(os.path.join(testharness_loc, 'strings.out'), "r") as stringsoutfile:
            stringsoutcontent = stringsoutfile.read()
            self.assertIn('bird: cockatoo', stringsoutcontent, "Testing that strings.out had the detected line")
            self.assertIn('The macaw flew the coop!', stringsoutcontent, "Testing that strings.out had the detected line")
            self.assertNotIn('The African Grey has a large vocabulary', stringsoutcontent, "Verify that the tool under test is not scanned for a dirty word entry")
        self.assertEqual(os.stat(os.path.join(testharness_loc, "strings.err")).st_size, 0,
                         "Testing that no error is thrown to strings.err")

    # Confirm that changes to PATH are registered and reported in the report generation file
    @subTestTags
    def test_path_changes(self, tag):
        # STRACE doesn't allow this? session = run(['./silentsentinel.sh', self.tmp_folder_loc, 'export', 'PATH=/test'])
        session = run(['./silentsentinel.sh', '-t', tag, '-P', '-C', '-U', '-r', 'm', self.tmp_folder_loc, 'sh', '-c', 'echo export PATH=\\$PATH:/dummy >> /etc/profile'])
        self.assertEqual(session.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        report_headers_list = self.get_headers_list()
        testharness_loc = os.path.join(self.tmp_folder_loc, 'testharness')

        # Checking for files after path tool is run
        self.assertNotEqual(os.stat(glob(os.path.join(testharness_loc, 'path', '*.out'))[0]).st_size, 0,
                            "Testing path output to file")
        self.assertTrue(glob(os.path.join(testharness_loc, 'path', '*.diff')),
                        "Testing path diff file creation")
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, 'path', 'path_0.diff')).st_size, 0,
                            "Testing that the differences between path files are recorded")
        self.assertIn('path', report_headers_list,
                      "Testing that path is in the report file")

        # Test that docker diff has the correct outputs
        self.assertIn('dockerdiff.out', os.listdir(testharness_loc),
                      "Testing docker diff file creation")
        with open(os.path.join(testharness_loc, 'dockerdiff.out'), "r") as dockerdiff:
            self.assertIn('C /etc/profile\n', dockerdiff.readlines(),
                          "Testing docker diff captured /etc/profile change")
        self.assertIn('dockerdiff.err', os.listdir(testharness_loc),
                      "Testing docker diff stderr file creation")
        self.assertEqual(os.stat(os.path.join(testharness_loc, 'dockerdiff.err')).st_size, 0,
                         "Testing no errors thrown in docker diff")
        self.assertIn('dockerdiff', report_headers_list,
                      'Test that docker diff is in report file')

    @subTestTags
    def test_netstat_changes(self, tag):
        if tag == 'alpine':
            # Alpine uses BusyBox netcat, which works differently than OpenBSD netcat which the rest of the distros we support use
            nc_command_line = 'mkfifo /tmp/ncfifo && exec 3<>/tmp/ncfifo && rm /tmp/ncfifo && { nc -v -l -p 8080 2>&3 & } && grep -qm 1 "listening on" <&3'
        else:
            nc_command_line = 'mkfifo /tmp/ncfifo && exec 3<>/tmp/ncfifo && rm /tmp/ncfifo && { nc -v -l 8080 2>&3 & } && grep -qm 1 "Listening on" <&3'
        session = run(['./silentsentinel.sh', '-t', tag, '-P', '-S', '-C', '-U', '-r', 'm', self.tmp_folder_loc, 'sh', '-c', nc_command_line])
        self.assertEqual(session.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        report_headers_list = self.get_headers_list()
        testharness_loc = os.path.join(self.tmp_folder_loc, 'testharness')

        # Test that netstat outputs to correct files and with actual data
        self.assertTrue(glob(os.path.join(testharness_loc, 'netstat', '*.out')),
                        "Testing netstat file creation")
        self.assertNotEqual(os.stat(glob(os.path.join(testharness_loc, 'netstat', '*.out'))[0]).st_size, 0,
                            "Testing netstat output to file")
        self.assertTrue(glob(os.path.join(testharness_loc, 'netstat', '*.diff')),
                        "Testing netstat diff file creation")
        with open(glob(os.path.join(testharness_loc, 'netstat', '*.diff'))[0], "r") as netstatdiff:
            self.assertIn(':8080', netstatdiff.read(), "Testing that the netstat diff showed port 8080 appearing")
        self.assertTrue(glob(os.path.join(testharness_loc, 'netstat', '*.err')),
                        "Testing no errors thrown in netstat")
        self.assertIn('netstat', report_headers_list,
                      'Test that netstat is in report file')

    @subTestTags
    def test_cpu_usage(self, tag):
        session = run(['./silentsentinel.sh', '-t', tag, '-P', '-S', '-C', '-U', '-r', 'm', self.tmp_folder_loc, 'timeout', '4', 'dd', 'if=/dev/zero', 'of=/dev/null'])
        self.assertEqual(session.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        report_headers_list = self.get_headers_list()
        cpu_stat_loc = os.path.join(self.tmp_folder_loc, 'testharness', 'cpu-stat')

        self.assertNotEqual(os.stat(glob(os.path.join(cpu_stat_loc, '*.out'))[0]).st_size, 0,
                            "Testing cpu usage output to file")
        self.assertTrue(glob(os.path.join(cpu_stat_loc, '*.diff')),
                        "Testing cpu usage diff file creation")
        self.assertIn('cpu-stat', report_headers_list,
                      "Testing that cpu usage is in the report file")
        self.assertNotEqual(os.stat(os.path.join(cpu_stat_loc, 'cpu-stat_0.diff')).st_size, 0,
                            "Testing that the differences between cpu usage files are recorded")

    @unittest.skipUnless(shutil.which("jq"), "config files require jq to be installed")
    @subTestTags
    def test_invoke_via_config_file(self, tag):
        # Create a test JSON config file and pass it to Silent Sentinel
        config_file_content = {
            "volumeMountDirectory": self.tmp_folder_loc,
            "toolUnderTest": [
                "sh",
                "-c",
                "echo \"# test modification\" >> /etc/crontab"
            ],
            "tag": tag,
            "ipv6": False,
            "analysisTools":
            {
                "clamscan": False,
                "coreDumps": False,
                "pspy": False,
                "strace": False,
                "suricata": False
            },
            "reportFormat": "markdown"
        }

        path_to_test_config_file = os.path.join(self.tmp_folder_loc, "test-config.json")
        with open(path_to_test_config_file, "w") as test_config_file:
            json.dump(config_file_content, test_config_file, indent=4)

        # Verify that we get an error code if we pass additional command flags along with -c path/to/config.json
        sessionExpectingFailure = run(['./silentsentinel.sh', '-c', path_to_test_config_file, '-P'])
        self.assertNotEqual(sessionExpectingFailure.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting non-zero value")

        # Run Silent Sentinel with a config file that disables the configurable analysis tools
        sessionExpectingSuccess = run(['./silentsentinel.sh', '-c', path_to_test_config_file])
        self.assertEqual(sessionExpectingSuccess.returncode, 0, "Silent Sentinel returned an unexpected exit code, expecting 0 (success)")

        testharness_loc = os.path.join(self.tmp_folder_loc, 'testharness')
        report_headers_list = self.get_headers_list()

        # Verify that the command under test ran as expected
        self.assertTrue(glob(os.path.join(testharness_loc, 'crontabs', '*.diff')),
                        "Testing crontabs diff file creation")
        self.assertIn('crontabs', report_headers_list,
                      "Testing that crontab is in the report file")
        self.assertNotEqual(os.stat(os.path.join(testharness_loc, 'crontabs', 'crontabs_0.diff')).st_size, 0,
                            "Testing that the differences between crontab files are recorded")

        # Verify that there are no clamscan files
        self.assertNotIn('clamscan.out', os.listdir(testharness_loc), "clamscan.out exists in the testharness folder")
        self.assertNotIn('clamscan.err', os.listdir(testharness_loc), "clamscan.err exists in the testharness folder")

        # Verify that there are no core dump files
        self.assertFalse(glob(os.path.join(testharness_loc, 'coredump-strings_*.out')), "A core dump files exists")

        # Verify that there are not pspy files
        self.assertNotIn('pspy.out', os.listdir(testharness_loc), "pspy.out exists in the testharness folder")
        self.assertNotIn('pspy.err', os.listdir(testharness_loc), "pspy.err exists in the testharness folder")

        # Verify that there is no strace json file
        self.assertNotIn('strace.json', os.listdir(testharness_loc), 'strace.json exists in the testharness folder')

        # Verify that there are no suricata files
        self.assertNotIn('raw-suricata-events.log', os.listdir(testharness_loc), 'raw-suricata-events file exists in the testharness folder')
        self.assertNotIn('suricata-statistics.out', os.listdir(testharness_loc), 'suricata statistics file exists in the testharness folder')
        self.assertNotIn('suricata.err', os.listdir(testharness_loc), 'suricata errors file exists in the testharness folder')

        # Verify that no header sections from the disabled analysis tools appear in the Markdown report
        self.assertNotIn("clamscan", report_headers_list, 'The header exists in the report')
        self.assertNotIn("pspy", report_headers_list, 'The header exists in the report')
        self.assertNotIn("strace", report_headers_list, 'The header exists in the report')
        self.assertNotIn("suricata-events", report_headers_list, 'The header exists in the report')
        self.assertNotIn("suricata-statistics", report_headers_list, 'The header exists in the report')

        # Check if any string in the set matches the wildcard pattern
        for current_header in report_headers_list:
            self.assertFalse(current_header.startswith("coredump-strings"), f'A header starting with coredump-strings exists in the report')

    def test_interpretation_guide_pdf_basevol(self):
        shutil.copy('./doc/interpretation-guide.md', self.tmp_folder_loc)
        session = run(['docker', 'run', '--rm', '-v', self.tmp_folder_loc + ':/vol', 'cmusei/silentsentinel-pandoc:latest', '-i'])
        self.assertEqual(session.returncode, 0, "docker run returned an unexpected exit code, expecting 0 (success)")

        self.assertTrue(glob(os.path.join(self.tmp_folder_loc, 'SilentSentinelInterpretationGuide.pdf')),
                        "Testing existence of Interpretation Guide PDF using default volume.")

    def test_interpretation_guide_pdf_newvol(self):
        shutil.copy('./doc/interpretation-guide.md', self.tmp_folder_loc)
        session = run(['docker', 'run', '--rm', '-v', self.tmp_folder_loc + ':/test-vol_123', 'cmusei/silentsentinel-pandoc:latest', '-i', '-v', '/test-vol_123'])
        self.assertEqual(session.returncode, 0, "docker run returned an unexpected exit code, expecting 0 (success)")

        self.assertTrue(glob(os.path.join(self.tmp_folder_loc, 'SilentSentinelInterpretationGuide.pdf')),
                        "Testing existence of Interpretation Guide PDF using custom volume.")

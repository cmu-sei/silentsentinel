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

# Install the tools required to compile dos2unix
apt-get update && apt-get install -y curl gcc make po4a

# Change to the volume mount directory where you downloaded the tarball
cd /vol

# Extract the tarball contents and move them to another location in the container
tar -xzf ./dos2unix-7.5.2.tar.gz || exit 1
mv dos2unix-7.5.2 /opt/dos2unix

# Compile dos2unix for the target testharness architecture
cd /opt/dos2unix
make && make install

# Run dos2unix to change the line endings of a test file
cd
dos2unix -n /opt/dos2unix/test/dos_dbl.txt /vol/newfile.txt
diff /opt/dos2unix/test/dos_dbl.txt /vol/newfile.txt >> /vol/newfile-diff.txt

exit 0

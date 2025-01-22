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

# assume we're building the report document unless the -i option is specified
BUILDDOC="report"
# assume we're using the default mounted volume location unless the -v option is specified
SHAREDVOL="/vol"

# parse the command arguments
# available options are:
#    -i                 to build interpretation guide instead of the report
#    -v <volume name>   to specify the name of the mounted volume
while getopts 'v:i' OPTION ; do
  case "${OPTION}" in 
    i)
      BUILDDOC="interpretation"
      ;;
    v)
      SHAREDVOL="${OPTARG}"
      ;;
  esac
done

# quick sanity check on the SHAREDVOL string
if [[ "${SHAREDVOL}" =~ ^\/[a-zA-Z0-9][a-zA-Z0-9_\/\-]*$ ]]; then
  # string valid; make sure this is a mount point
  if ! [ -d "${SHAREDVOL}" ] ; then
    # not a valid volume mount
    echo "ERROR - Shared volume not found."
    exit 1
  fi
else
  # not a valid volume definiton
  echo "ERROR - input parameter invalid; must specify absolute path."
  exit 1
fi

# now that the SHAREDVOL is validated, set some more parameters
if [[ "${BUILDDOC}" == "report" ]] ; then
  HEADERFILE="report-pandoc-header.txt"
  OUTFILE="SilentSentinelReport"
  INFILE=$(find "${SHAREDVOL}" -maxdepth 1 -type f -name "silentsentinel_report_*_report.md" | sort | tail -1)
  # sample INFILE filename for report: silentsentinel_report_2024-03-20_17-05-05.200957_report.md
else
  HEADERFILE="interpretation-pandoc-header.txt"
  OUTFILE="SilentSentinelInterpretationGuide"
  INFILE=$(find "${SHAREDVOL}" -maxdepth 1 -type f -name "README.md")
fi

# Set the name of the latext template file
TEMPLATE="default-pandoc-latex.template"

if [ -z "$INFILE" ] ; then
  if [[ "${BUILDDOC}" == "report" ]] ; then
    echo "ERROR - markdown source file not found. Must mount volume containing Silent Sentinel markdown report."
    exit 1
  else
    echo "ERROR - markdown source file not found. Must mount a volume containing README.md file."
    exit 1
  fi
else
  if [[ "${BUILDDOC}" == "report" ]] ; then
    # Get the base filename
    INBASE=$(basename "$INFILE" .md)
  fi
fi

# Combine the pandoc header and the markdown file
cat "${HEADERFILE}" >> ${OUTFILE}.md
cat <<\EOF >> ${OUTFILE}.md


\clearpage


EOF
cat "${INFILE}" >> ${OUTFILE}.md

# Get the latest latex template from pandoc
echo -n "Obtaining latest latex template for pandoc..."
pandoc -D latex > $TEMPLATE || { echo "ERROR - failed to get the latex template from pandoc." ; exit 1 ; }
echo "done."

# Build the tex document from the markdown file
echo -n "Generating ${OUTFILE}.tex..."
pandoc \
  -f markdown \
  -t latex \
  --table-of-contents \
  --pdf-engine=xelatex \
  --template "${TEMPLATE}" \
  -o "${OUTFILE}.tex" \
  "${OUTFILE}.md"
echo "done."

# Building the pdf with all the components requires multiple rounds
# draft 1 - to generate required files
echo -n "Generating ${OUTFILE}.pdf - draft 1..."
xelatex -interaction=batchmode "${OUTFILE}.tex" &> /dev/null
echo "done."

# draft 2 - to add page numbers
echo -n "Generating ${OUTFILE}.pdf - draft 2..."
xelatex -interaction=batchmode "${OUTFILE}.tex" &> /dev/null
echo "done."

# draft 3 - to incorporate all files into the final pdf
echo -n "Generating ${OUTFILE}.pdf - final..."
xelatex -interaction=batchmode "${OUTFILE}.tex" &> /dev/null
echo "done."

# if all the builds were successful, copy out the pdf
echo -n "Gathering pdf..."
if [[ "${BUILDDOC}" == "report" ]] ; then
  cp "${OUTFILE}.pdf" "${SHAREDVOL}/${INBASE}.pdf"
else
  cp "${OUTFILE}.pdf" "${SHAREDVOL}/."
fi
echo "done."

exit 0

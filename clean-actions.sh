#!/bin/bash
# Title: clean-actions.sh
# Description: Cleanup AWS action file so it works with Python's config parser

# Set action file from command line argument
action_file=${1}

if [[ ! -f ${action_file} ]]; then
  echo -e "-> No action taken due to no file argument provided."
  exit 1
fi

# Change Action word from AWS Policy JSON to Config Parser key
sed -i 's/"Action":/Action =/' ${action_file}

# Capture first line to check for service keyword later
first_line=$(head -1 ${action_file})

# See if the service keyword exists
echo ${first_line} | grep 'service' &> /dev/null
grep_result=$?

# Insert service definition if it isn't already there for Config Parser
if [[ ${grep_result} -eq 1 ]]; then
  sed -i '1 i\[service]' ${action_file}
fi


#!/usr/bin/env python3
"""
Title: AWS Policy Simulator
Description: Check if provided service actions are allowed for an AWS user
Author: Bill Howe
Date: See 'git log -p <filename>'
Recent Changes: See 'git log -p <filename>'
"""

#=======================
# Import Modules
#=======================
# argparse - Command line arguments
import argparse

# os.path - In order to check if actions is a file
import os.path

# ConfigParser - Read service action configuration files
import configparser

# json - Config files use a list which can be parsed by json
import json

# itemgetter - sort a list of dictionaries by key
from operator import itemgetter

# boto3 - AWS SDK for Python
import boto3

#=======================
# Get Script Arguments
#=======================
# Build argument parser information
parser = argparse.ArgumentParser(description="Check if provided service actions are allowed for an AWS user. This script assumes your AWS Credentials are configured (~/.aws/credentials) with your access key.")
parser.add_argument("-i", "--id", help="AWS Account ID [optional]", required=False)
parser.add_argument("-u", "--user", help="AWS User Name [user or role option required]", required=False)
parser.add_argument("-r", "--role", help="AWS Role Name [user or role option required]", required=False)
parser.add_argument("-a", "--actions", help="Action Names [required] (comma separated string or filename)", required=True)
parser.add_argument("-v", "--verbose", help="Verbose output", required=False, action="store_true")
args = vars(parser.parse_args())

#=======================
# Configure Settings
#=======================

#-- AWS Credentials file check --##
# Location of User's AWS credentials file
aws_user_creds = os.environ.get('HOME') + "/.aws/credentials"

# Exit if we got a user id and a role
if args['user'] and args['role']:
  print("-> Error! Do not set both a user and a role, only use one. Exiting...")
  exit(1)

# Exit if we don't have a user and role set
elif not args['user'] and not args['role']:
  print("-> Error! Need to set a user or a role to run simulations for. Exiting...")
  exit(1)


# Set AWS Account ID
if args['id']:
  # Set Account ID from command line
  aws_account_id = args['id']
else:
  # Set dynamically
  sts_client = boto3.client('sts')
  aws_account_id = sts_client.get_caller_identity()["Account"]


# Build settings if a user is set
if args['user']:
  # If the AWS Credentials file does not exist, don't run
  if not os.path.isfile(aws_user_creds):
    print("-> Error! User's AWS credentials file (" + aws_user_creds + ") does not exist. Exiting...")
    exit(1)

  # Set Username from argument
  aws_user_name = args['user']

  # Build User ARN from provided AWS Account ID and user name
  sim_policy_arn = "arn:aws:iam::" + aws_account_id + ":user/" + aws_user_name

  # Get IAM Client Object in order to run policy simulation
  iam_client = boto3.client('iam')

# Build settings if a role is set
elif args['role']:
  # Set role name from argument
  aws_role_name = args['role']

  # Retrieve credentials from current session's running role
  session = boto3.Session()
  credentials = session.get_credentials()

  # Credentials are refreshable, so accessing your access key / secret key
  # separately can lead to a race condition. Use this to get an actual matched set
  credentials = credentials.get_frozen_credentials()
  access_key = credentials.access_key
  secret_key = credentials.secret_key

  # Build Role ARN from provided AWS account id and role name
  sim_policy_arn = "arn:aws:iam::" + aws_account_id + ":role/" + aws_role_name

  # Get IAM Client Object, using role temp credentials, in order to run policy simulation
  iam_client = boto3.client(
    'iam',
    aws_access_key_id = access_key,
    aws_secret_access_key = secret_key,
    aws_session_token = credentials.token,
  )

# Check to see if actions is a file
if os.path.isfile(args['actions']):
  # It is a file, read the config, parse json list
  config = configparser.ConfigParser()
  config.read(args['actions'])
  sim_policy_actions = json.loads(config.get("service", "Action"))
else:
  # Not a file, convert comma serpated string into action list
  sim_policy_actions = args['actions'].split(",")

#=======================
# Simulate the Policy
#=======================

# Paginator for long responses
paginator = iam_client.get_paginator('simulate_principal_policy')

# Run simulation - with pagination
response = paginator.paginate(
  PolicySourceArn = sim_policy_arn,
  ActionNames = sim_policy_actions,
  PaginationConfig={
        'MaxItems': 100,
  }
)

#=======================
# Output Results
#=======================
print("-- Policy Simulation Results --")
print("-> AWS Account: " + aws_account_id)

# Status message for user or role name
if args['user']:
  print("-> User: " + aws_user_name + "\n")
elif args['role']:
  print("-> Role: " + aws_role_name + "\n")

##-- Build a list of results for later sorting --##
results_list = []
for entry in response:
  # For each "page" of entries in the response

  # Verbose JSON output if requested
  if args['verbose'] == True:
    print(entry['EvaluationResults'], "\n")

  for result in entry['EvaluationResults']:
    # For each result, add the action name and decision (allowed/denied) to the results list
    results_list.append( { "ActionName" : result['EvalActionName'], "EvalDecision" : result['EvalDecision'] })

# Sort all results by the dictionary key Action Name
sorted_results = sorted(results_list, key = itemgetter('ActionName'))

# Display Sorted Results
for action in sorted_results:
  print("Action Name: " + action['ActionName'] + ", Eval Decision: " + action['EvalDecision'])


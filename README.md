# AWS IAM Policy Sim

AWS IAM Policy Simulator.

----

## Directories

- aws_policy_actions -> Amazon services and available actions per service.

## Files

- aws-policy-simulator.py -> Check if provided service actions are allowed for an AWS user
- clean-actions.sh -> Cleanup AWS IAM JSON policies in order for python config parser to use them in the aws-policy-simulator.py script.

----

## Script requirements

- Python3
- boto3

Virtual environment installation example

```bash
# Create virtual environment
python3 -m venv polsim

# Copy requirements file into new dir
cp requirements.txt polsim/

# Activate virtual environment
cd polsim
source bin/activate

# Install requirements
pip install -r requirements.txt
```

## Usage

- Configure your AWS access keys (~/.aws/credentials) OR run on an instance with desired role attached.

```bash
usage: aws-policy-simulator.py [-h] [-i ID] [-u USER] [-r ROLE] -a ACTIONS
                               [-v]

optional arguments:
  -h, --help            show this help message and exit
  -i ID, --id ID        AWS Account ID [optional]
  -u USER, --user USER  AWS User Name [user or role option required]
  -r ROLE, --role ROLE  AWS Role Name [user or role option required]
  -a ACTIONS, --actions ACTIONS
                        Action Names [required] (comma separated string or
                        filename)
  -v, --verbose         Verbose output
```

### Example: Single Action

```bash
./aws-policy-simulator.py --user yoda --actions 's3:ListBucket'
-- Policy Simulation Results --
-> AWS Account: <id output here>
-> User: yoda

Action Name: s3:ListBucket, Eval Decision: allowed
```

### Example: Multiple Actions

```bash
./aws-policy-simulator.py --user yoda --actions 's3:ListBucket,s3:GetObject'
-- Policy Simulation Results --
-> AWS Account: <id output here>
-> User: yoda

Action Name: s3:GetObject, Eval Decision: allowed
Action Name: s3:ListBucket, Eval Decision: allowed
```

### Example: Single service, all actions

```bash
./aws-policy-simulator.py --user yoda --actions aws_policy_actions/actions_well_architected
-- Policy Simulation Results --
-> AWS Account: <id output here>
-> User: yoda

Action Name: wellarchitected:CreateWorkload, Eval Decision: implicitDeny
Action Name: wellarchitected:GetWorkload, Eval Decision: allowed
Action Name: wellarchitected:ListWorkloads, Eval Decision: allowed
```

### Example: All services, all actions

```bash
# Create a results directory
mkdir results

# Execute a loop and capture results
for action in $(ls aws_policy_actions/); do ./aws-policy-simulator.py --user yoda --actions aws_policy_actions/${action} | tee results/result_${action} 2>&1 ; sleep 1 ; done
```

Note: The sleep is used to avoid AWS rate limiting.

----

## Creating the action files

In order to create/update the action files:

- Login to the AWS Web Console
- Navigate to: Services > IAM > Policies
  - Click "Create policy"
  - Click "Choose a service" (and select desired service)
  - Individually, check each box under 'Access level' (all actions in the JSON output will NOT show up if you check the 'All actions' with a '\*')
  - If any resource types are required, click "Resources", then select "All resources"
  - At the top, click the "JSON" tab
  - Copy from "Action"  to the ending ']' that completes the Action part of the JSON.
  - Paste into action the file (replacing all contents if it already exists)
  - Run the clean-actions script against the file

```bash
# Adds the '[service]' header required for config parser
# Converts "Action" to Action =  required for config parser
./clean-actions.sh aws_policy_actions/actions_<servicename>
```

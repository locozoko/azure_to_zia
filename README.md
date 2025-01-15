# Azure Firewall to ZIA Firewall Rules Automation Script

## Overview

This Python script automates the process of reading Azure Firewall rules and creating corresponding resources in the Zscaler Internet Access (ZIA) platform. It ensures that firewall policies from Azure are mirrored in ZIA, including IP groups, network services, network service groups, and firewall rules.

Key Features 1. Azure Integration: Fetches Azure Firewall rules and IP groups from a specified subscription, resource group, and firewall policy. 2. ZIA Integration: Authenticates with the ZIA API to retrieve and create resources, including:

- IP Source Groups

- Network Services

- Network Service Groups

- Firewall Rules 3. Incremental Creation: Avoids duplication by checking for existing resources before creating new ones. 4. Customizable Execution: Allows optional targeting of specific Azure rules (TARGET_AZURE_RULE_NAME) or all rules. 5. Interactive Prompts: Provides a prompt before starting Zscaler object creation for user confirmation. 6. Error Handling: Logs errors, including invalid inputs, rate limits, and API failures, while attempting retries when possible.

## Prerequisites

1. Python Environment:

- Install Python 3.7 or later.

- Optionally, set up a virtual environment:

```bash
python3 -m venv zsvenv && source zsvenv/bin/activate
```

2\. Required Python Libraries:

Install the following libraries using pip:

```bash
pip install azure-identity azure-mgmt-network azure-mgmt-resource requests
```

3\. Azure Credentials:

- Ensure that you have valid Azure credentials configured for the DefaultAzureCredential class.

- Update the following variables in the script:

- SUBSCRIPTION_ID

- RESOURCE_GROUP

- FIREWALL_POLICY_NAME

4\. ZIA Credentials:

- Update the following variables with your ZIA account details:

- ZIA_API_URL

- ZIA_USERNAME

- ZIA_PASSWORD

- ZIA_API_KEY

5\. Firewall API Permissions:

- Ensure the Azure account has Reader access to the subscription/resource group.

- Ensure the ZIA account has API access for firewall-related resources.

## Usage

1. Update Variables:

Edit the script to fill in the required Azure and ZIA credentials. 2. Run the Script:

Execute the script with Python:

```bash
python azurefw-to-ziafirewall.py
```

3\. Interactive Confirmation:

- The script prompts you to confirm whether to proceed with creating Zscaler objects.

- If you type "n" or "no," the script exits gracefully without making any changes.

## What the Script Does

1. Fetch Data:

- Retrieves Azure IP Groups and Firewall Rules.

- Fetches existing ZIA IP Source Groups, Network Services, Service Groups, and Firewall Rules.

- Exports all data to JSON files for reference. 2. Create Resources:

- IP Source Groups: Creates missing ZIA IP Source Groups based on Azure IP Groups.

- Network Services: Creates missing ZIA Network Services for each protocol/port combination in Azure rules.

- Network Service Groups: Creates ZIA Network Service Groups for each Azure rule referencing relevant network services.

- Firewall Rules: Creates ZIA Firewall Rules matching Azure Firewall Rules. 3. Activate Changes:

- If new ZIA Firewall Rules are created, the script activates the pending changes in ZIA.

Optional Configuration

- Target Specific Azure Rule:

To process only one specific Azure rule, set the TARGET_AZURE_RULE_NAME variable to the name of the rule:

TARGET_AZURE_RULE_NAME = "customhttpport"

Leave it blank ("") to process all Azure rules.

Error Handling

- The script logs errors for any failed API calls or invalid inputs.

- Rate limits from the ZIA API are handled with retries after a short delay.

- Invalid or incomplete data (e.g., missing ports or protocols) are skipped with appropriate warnings.

Output

- The script creates or skips resources as necessary and logs all actions.

- JSON files containing fetched data are saved in the same directory for reference:

- azure_ip_groups.json

- azure_firewall_rules.json

- zscaler_ip_source_groups.json

- zscaler_network_services.json

- zscaler_network_service_groups.json

- zscaler_firewall_rules.json

## Support

For any issues or questions, contact Zoltan at zkovacs@zscaler.com. This script is a best-effort basis and not officially supported by Zscaler.

This documentation should help customers understand, configure, and run the script effectively.

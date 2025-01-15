# Azure Firewall to ZIA Firewall Rules Automation Script

<a href="https://www.loom.com/embed/7d33dfc5ca2c416182086732381eb1cc?sid=40e76d3e-c218-470f-8e95-840fc655cc88" target="_blank">Watch the video demonstration on Loom</a>

## Overview

This Python script automates the process of reading Azure Firewall rules and creating corresponding resources in the Zscaler Internet Access (ZIA) platform. It ensures that firewall policies from Azure are mirrored in ZIA, including IP groups, network services, network service groups, and firewall rules.

## Key Features

1. **Azure Integration:** Fetches Azure Firewall rules and IP groups from a specified subscription, resource group, and firewall policy. 2. ZIA Integration: Authenticates with the ZIA API to retrieve and create resources, including:

- IP Source Groups

- Network Services

- Network Service Groups

- Firewall Rules

3. **Incremental Creation:** Avoids duplication by checking for existing resources before creating new ones.
4. **Customizable Execution:** Allows optional targeting of specific Azure rules (TARGET_AZURE_RULE_NAME) or all rules.
5. **Interactive Prompts:** Provides a prompt before starting Zscaler object creation for user confirmation.
6. **Error Handling:** Logs errors, including invalid inputs, rate limits, and API failures, while attempting retries when possible.

## Prerequisites

1. **Python Environment:**

- Install Python 3.7 or later.

- Optionally, set up a virtual environment:

```bash
python3 -m venv zsvenv && source zsvenv/bin/activate
```

2. Required Python Libraries:

Install the following libraries using pip:

```bash
pip install azure-identity azure-mgmt-network azure-mgmt-resource requests
```

3. **Azure Credentials:**

- Ensure that you have valid Azure credentials configured for the DefaultAzureCredential class.

- Update the following variables in the script:

- SUBSCRIPTION_ID

- RESOURCE_GROUP

- FIREWALL_POLICY_NAME

4. **ZIA Credentials:**

- Update the following variables with your ZIA account details:

- ZIA_API_URL

- ZIA_USERNAME

- ZIA_PASSWORD

- ZIA_API_KEY

5. **Firewall API Permissions:**

- Ensure the Azure account has Reader access to the subscription/resource group.

- Ensure the ZIA account has API access for firewall-related resources.

## Usage

1. **Update Variables:**

Edit the script to fill in the required Azure and ZIA credentials.

2. **Run the Script:**

Execute the script with Python:

```bash
python azurefw-to-ziafirewall.py
```

3. **Interactive Confirmation:**

- The script prompts you to confirm whether to proceed with creating Zscaler objects.

- If you type "n" or "no," the script exits gracefully without making any changes in Zscaler (it will only get the data)

## What the Script Does

1. **Authenticates with Azure and Zscaler**

- Logs into Azure to execute commands using Azure CLI
- Logs into Zscaler Internet Access to execute APIs

2. **Fetches Data from Azure and Zscaler**

- Gets Azure IP Groups
- Gets Azure Firewall Rules
- Gets Zscaler IP Source Groups
- Gets Zscaler Network Services
- Gets Zscaler Network Service Groups
- Gets Zscaler Firewall Rules

3. **Exports Data for Reference and Debugging from Azure and Zscaler**

- Saves Azure data to json files (same directory as script)
- Saves Zscaler data to json files (same directory as script)

4. **Processes Azure Firewall Rules**

- Maps Azure Firewall Rule components to correspending Zscaler objects

5. **Creates Missing Zscaler objects**

- Maps Azure IP groups to Zscaler IP Source Groups
- Converts Azure protocols and ports to Network Services (per unique combination)
- Groups Network Services into logical groups to match Azure Firewall rules
- Creates Zscaler Firewall Rules to enforce policies that mirror Azure Firewall Rules

6. **Handles Dependencies Automatically**

- Ensures all required Zscaler objects are created before associating with Firewall Rules

7. **Activates Zscaler changes**

- Once all objects in Zscaler are created the script automatically activates changes

8. **Prompts user to confirm attempt to create Zscaler objects after fetching data**

- Allows you to run the script to only fetch data or to also attempt creating Zscaler objects

## Support

This script is a best-effort basis and not officially supported by Zscaler. Please update/edit as needed

This documentation should help customers understand, configure, and run the script effectively.

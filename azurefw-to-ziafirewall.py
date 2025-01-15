# This script was written by Zoltan Kovacs (zkovacs@zscaler.com) for Zscaler customer usage
# It reads Azure IP Groups, Azure Firewall rules, Zscaler ZIA Source IP Groups, Zscaler ZIA Network Services/Groups, and Zscaler ZIA Firewall Rules
# It then creates new ZIA resources based on Azure
# Prerequisite 1: You might need to run in virtual environment: python3 -m venv zsvenv && source zsvenv/bin/activate
# Prerequisite 2: pip install azure-identity azure-mgmt-network azure-mgmt-resource requests
# Prerequisite 3: Fill out the variables such as Azure Credentials and ZIA Credentials in the script
# Run the script: python azurefw-to-ziafirewall.py
import os
import requests
import json
import time
import logging
import sys
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient

# Azure credentials and setup
SUBSCRIPTION_ID = "<REPLACE_ME>"
FIREWALL_POLICY_NAME = "<REPLACE_ME>"
RESOURCE_GROUP = "<REPLACE_ME>"

# Zscaler credentials
ZIA_API_URL = "https://zsapi.zscaler.net/api/v1"
ZIA_USERNAME = "<REPLACE_ME>"
ZIA_PASSWORD = "<REPLACE_ME>"
ZIA_API_KEY = "<REPLACE_ME>"

# File paths for exported data
IP_GROUPS_FILE = "azure_ip_groups.json"
FIREWALL_RULES_FILE = "azure_firewall_rules.json"
ZIA_SOURCE_GROUPS_FILE = "zscaler_ip_source_groups.json"

# Option to test a single rule or all of them (leave blank for all)
TARGET_AZURE_RULE_NAME = ""  # Example: "customhttpport"

# Enable logging
logging.basicConfig(level=logging.INFO) #set to debug if script fails
logging.getLogger("urllib3").setLevel(logging.INFO) #set to debug if script fails

# Prompt to continue Zscaler object creation
def prompt_confirmation(prompt):
    while True:
        response = input(f"{prompt} (y/n): ").strip().lower()
        if response in ["y", "yes"]:
            return True
        elif response in ["n", "no"]:
            logging.info("Exiting script as per user selection.")
            sys.exit(0)  # Exit the script gracefully
        else:
            print("Invalid input. Please type 'y' or 'n'.")

# Azure authentication
def authenticate_to_azure():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        for subscription in subscription_client.subscriptions.list():
            if subscription.subscription_id.strip().lower() == SUBSCRIPTION_ID.strip().lower():
                return credential
        raise Exception("Specified subscription not found.")
    except Exception as e:
        logging.error(f"Failed to authenticate to Azure: {e}")
        exit(1)

# Export data to JSON
def export_to_json(data, filename):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        logging.info(f"Exported data to {filename}")
    except Exception as e:
        logging.error(f"Failed to export data to {filename}: {e}")

# Fetch Azure Firewall Rules
def fetch_firewall_rules(credential):
    API_VERSION = "2023-05-01"
    url = f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Network/firewallPolicies/{FIREWALL_POLICY_NAME}/ruleCollectionGroups?api-version={API_VERSION}"
    token = credential.get_token("https://management.azure.com/.default").token
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    rule_collection_groups = response.json().get("value", [])

    rules = []
    for group in rule_collection_groups:
        group_name = group.get("name")
        rule_collections = group.get("properties", {}).get("ruleCollections", [])

        for collection in rule_collections:
            collection_name = collection.get("name")
            rules_in_collection = collection.get("rules", [])
            for rule in rules_in_collection:
                rule_name = rule.get("name")
                rule_type = rule.get("ruleType")
                action = collection.get("action", {}).get("type")

                if rule_type == "ApplicationRule":
                    rules.append({
                        "rule_collection_group": group_name,
                        "rule_collection": collection_name,
                        "rule_name": rule_name,
                        "rule_type": rule_type,
                        "action": action,
                        "source_addresses": rule.get("sourceAddresses", []),
                        "source_ip_groups": rule.get("sourceIpGroups", []),
                        "target_fqdns": rule.get("targetFqdns", []),
                        "protocols": [{"protocol": p.get("protocolType"), "port": p.get("port")} for p in rule.get("protocols", [])]
                    })
                elif rule_type == "NetworkRule":
                    rules.append({
                        "rule_collection_group": group_name,
                        "rule_collection": collection_name,
                        "rule_name": rule_name,
                        "rule_type": rule_type,
                        "action": action,
                        "source_addresses": rule.get("sourceAddresses", []),
                        "source_ip_groups": rule.get("sourceIpGroups", []),
                        "destination_addresses": rule.get("destinationAddresses", []),
                        "destination_ports": rule.get("destinationPorts", []),
                        "ip_protocols": rule.get("ipProtocols", [])
                    })

    logging.info(f"Total Firewall Rules Found: {len(rules)}")
    return rules

# Fetch Azure IP Groups
def fetch_azure_ip_groups(credential):
    API_VERSION = "2023-05-01"
    url = f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Network/ipGroups?api-version={API_VERSION}"
    token = credential.get_token("https://management.azure.com/.default").token
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    ip_groups = response.json().get("value", [])

    azure_ip_groups = [
        {"name": group["name"], "ip_addresses": group["properties"]["ipAddresses"]}
        for group in ip_groups
    ]
    logging.info(f"Total Azure IP Groups Found: {len(azure_ip_groups)}")
    return azure_ip_groups

# Zscaler authentication
def obfuscate_api_key(api_key):
    now = int(time.time() * 1000)
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    obfuscated_key = "".join(api_key[int(n[i])] for i in range(len(n))) + "".join(api_key[int(r[j]) + 2] for j in range(len(r)))
    return obfuscated_key, now

def zscaler_authenticate():
    obfuscated_key, timestamp = obfuscate_api_key(ZIA_API_KEY)
    payload = {
        "username": ZIA_USERNAME,
        "password": ZIA_PASSWORD,
        "apiKey": obfuscated_key,
        "timestamp": str(timestamp)
    }
    try:
        response = requests.post(f"{ZIA_API_URL}/authenticatedSession", json=payload)
        response.raise_for_status()
        return response.headers.get("Set-Cookie")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error authenticating with ZIA: {e}")
        exit(1)

# Fetch Zscaler Firewall Rules
def get_zscaler_firewall_rules(zia_token):
    headers = {"Cookie": zia_token, "Content-Type": "application/json"}
    try:
        logging.debug("Fetching ZIA firewall rules...")
        logging.debug(f"Headers: {headers}")
        response = requests.get(f"{ZIA_API_URL}/firewallFilteringRules", headers=headers)
        response.raise_for_status()
        rules = response.json()
        logging.info(f"Total ZIA Firewall Rules Found: {len(rules)}")
        logging.debug(f"ZIA Firewall Rules Response: {json.dumps(rules, indent=4)}")
        return rules
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching ZIA Firewall Rules: {e}")
        return []

# Fetch Zscaler IP Source Groups
def get_zscaler_ip_source_groups(zia_token):
    headers = {"Cookie": zia_token, "Content-Type": "application/json"}
    try:
        response = requests.get(f"{ZIA_API_URL}/ipSourceGroups", headers=headers)
        response.raise_for_status()
        groups = response.json()
        logging.info(f"Total Zscaler IP Source Groups Found: {len(groups)}")
        logging.debug(f"Zscaler IP Source Groups Response: {json.dumps(groups, indent=4)}")
        return groups
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching Zscaler IP Source Groups: {e}")
        return []
    
# Fetch Zscaler Network Services
def get_zscaler_network_services(zia_token):
    """Fetch existing ZIA network services."""
    headers = {"Cookie": zia_token, "Content-Type": "application/json"}
    try:
        response = requests.get(f"{ZIA_API_URL}/networkServices", headers=headers)
        response.raise_for_status()
        services = response.json()
        logging.info(f"Total ZIA Network Services Found: {len(services)}")
        return services
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching ZIA Network Services: {e}")
        return []
    
# Fetch Zscaler Network Service Groups
def get_zscaler_network_service_groups(zia_token):
    """Fetch existing ZIA network service groups."""
    headers = {"Cookie": zia_token, "Content-Type": "application/json"}
    try:
        response = requests.get(f"{ZIA_API_URL}/networkServiceGroups", headers=headers)
        response.raise_for_status()
        groups = response.json()
        logging.info(f"Total ZIA Network Service Groups Found: {len(groups)}")
        return groups
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching ZIA Network Service Groups: {e}")
        return []
    
# Create Network Services
def create_zia_network_services(azure_protocols, zia_network_services, zia_token):
    """
    Create missing ZIA network services based on Azure firewall rules' protocols and ports.
    Handles ApplicationRule and NetworkRule data.
    """
    existing_services = {service["name"]: service["id"] for service in zia_network_services}
    created_services = []

    for protocol in azure_protocols:
        protocol_type = protocol.get("protocol", "").lower()
        port = protocol.get("port")

        if not protocol_type or port is None:
            logging.warning(f"Skipping invalid protocol: {protocol}")
            continue

        service_name = f"AzureFw_{protocol_type.upper()}_{port}"
        if service_name in existing_services:
            logging.info(f"Skipping existing ZIA Network Service: {service_name}")
            created_services.append({"name": service_name, "id": existing_services[service_name]})
            continue

        # Build payload
        payload = {
            "name": service_name,
            "type": "CUSTOM",
            "srcTcpPorts": [{"start": port}] if protocol_type in ["http", "tcp"] else [],
            "destTcpPorts": [{"start": port}] if protocol_type in ["http", "tcp"] else [],
            "srcUdpPorts": [{"start": port}] if protocol_type == "udp" else [],
            "destUdpPorts": [{"start": port}] if protocol_type == "udp" else [],
            "description": f"Created for Azure Protocol {protocol_type.upper()}:{port}",
        }

        # Debugging payload
        logging.debug(f"Payload for creating network service: {json.dumps(payload, indent=4)}")

        # Create service
        retry_attempts = 3
        while retry_attempts > 0:
            try:
                response = requests.post(
                    f"{ZIA_API_URL}/networkServices",
                    headers={"Cookie": zia_token, "Content-Type": "application/json"},
                    json=payload,
                )
                response.raise_for_status()
                created_service = response.json()
                created_services.append(created_service)
                logging.info(f"Created ZIA Network Service: {service_name}")
                break
            except requests.exceptions.HTTPError as e:
                if response.status_code == 429:  # Handle rate limiting
                    retry_after = int(response.headers.get("Retry-After", 1))
                    logging.warning(f"Rate limit hit. Retrying after {retry_after} seconds...")
                    time.sleep(retry_after)
                    retry_attempts -= 1
                else:
                    logging.error(f"Error creating ZIA Network Service '{service_name}': {response.text}")
                    break
            except requests.exceptions.RequestException as e:
                logging.error(f"Error creating ZIA Network Service '{service_name}': {e}")
                break

        if retry_attempts == 0:
            logging.warning(f"Failed to create network service: {service_name}")

    logging.info(f"Total Created Network Services: {len(created_services)}")
    return created_services

# Create Zscaler Network Service Groups
def create_zia_network_service_groups(rule_name, services, zia_service_groups, zia_token):
    """
    Create a ZIA network service group for a given firewall rule.
    """
    if not services:
        logging.warning(f"Skipping network service group creation for rule '{rule_name}': No valid services.")
        return None

    group_name = f"AzureFw_{rule_name}_NSG"
    existing_service_groups = {group["name"]: group["id"] for group in zia_service_groups}

    if group_name in existing_service_groups:
        logging.info(f"Skipping creation of existing ZIA Service Group: {group_name}")
        return {"id": existing_service_groups[group_name]}

    payload = {
        "name": group_name,
        "services": [{"id": service["id"]} for service in services],
        "description": f"Service Group for Azure Rule {rule_name}",
    }

    logging.debug(f"Payload for Service Group '{group_name}': {json.dumps(payload, indent=4)}")

    try:
        response = requests.post(
            f"{ZIA_API_URL}/networkServiceGroups",
            headers={"Cookie": zia_token, "Content-Type": "application/json"},
            json=payload,
        )
        response.raise_for_status()
        created_group = response.json()
        logging.info(f"Created ZIA Service Group: {created_group['name']}")
        return created_group
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to create Service Group '{group_name}': {e}")
        return None

# Create missing ZIA IP Source Groups
def create_zia_ip_source_groups(azure_ip_groups, zia_source_groups, zia_token):
    existing_zia_groups = {group["name"]: group["id"] for group in zia_source_groups}
    new_groups = []

    for azure_group in azure_ip_groups:
        group_name = azure_group["name"]
        ip_addresses = azure_group.get("ip_addresses", [])

        if not ip_addresses:
            logging.warning(f"Skipping Azure IP Group '{group_name}': No IP addresses found.")
            continue

        if group_name in existing_zia_groups:
            logging.info(f"Skipping existing ZIA IP Source Group: {group_name}")
            continue

        payload = {
            "name": group_name,
            "ipAddresses": ip_addresses,
            "description": f"Created from Azure IP Group '{group_name}'"
        }

        try:
            response = requests.post(f"{ZIA_API_URL}/ipSourceGroups", headers={"Cookie": zia_token, "Content-Type": "application/json"}, json=payload)
            response.raise_for_status()
            created_group = response.json()
            new_groups.append(created_group)
            logging.info(f"Created ZIA IP Source Group: {group_name}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error creating ZIA IP Source Group '{group_name}': {e}")

    all_groups = zia_source_groups + new_groups
    export_to_json(all_groups, ZIA_SOURCE_GROUPS_FILE)
    return all_groups

# Create ZIA Firewall Rules
def create_zia_firewall_rules(
    azure_firewall_rules, zia_firewall_rules, zia_source_groups, zia_service_groups, zia_token
):
    """Create missing Zscaler Firewall Rules based on Azure Firewall Rules."""
    existing_zia_rules = {rule["name"]: rule["order"] for rule in zia_firewall_rules}
    existing_source_groups = {group["name"]: group["id"] for group in zia_source_groups}
    existing_service_groups = {group["name"]: group for group in zia_service_groups}

    # Start ordering after existing ZIA rules
    max_existing_order = max([rule["order"] for rule in zia_firewall_rules], default=0)
    next_order = max_existing_order + 1
    new_rules = []

    for azure_rule in azure_firewall_rules:
        rule_name = azure_rule["rule_name"]

        # Skip if rule already exists in ZIA
        if rule_name in existing_zia_rules:
            logging.info(f"Skipping existing ZIA Firewall Rule: {rule_name}")
            continue

        # Find the network service group for the rule
        service_group_name = f"AzureFw_{rule_name}_NSG"
        service_group = existing_service_groups.get(service_group_name)

        # Refresh service groups from ZIA if not found
        if not service_group:
            logging.warning(f"Service group '{service_group_name}' not found. Refreshing service groups...")
            zia_service_groups = get_zscaler_network_service_groups(zia_token)
            existing_service_groups = {group["name"]: group for group in zia_service_groups}
            service_group = existing_service_groups.get(service_group_name)

        if not service_group:
            logging.error(f"Failed to find service group '{service_group_name}' for rule '{rule_name}'. Skipping...")
            continue

        # Map source IP groups
        src_ip_groups = []
        if azure_rule.get("source_ip_groups"):
            for azure_ip_group in azure_rule["source_ip_groups"]:
                group_name = azure_ip_group.split("/")[-1]  # Extract group name
                if group_name in existing_source_groups:
                    src_ip_groups.append({"id": existing_source_groups[group_name]})
                else:
                    logging.warning(f"Source IP Group '{group_name}' not found in ZIA. Skipping...")

        # Prepare the payload for the firewall rule
        payload = {
            "name": rule_name,
            "action": "ALLOW" if azure_rule["action"].lower() == "allow" else "BLOCK_DROP",
            "state": "ENABLED",
            "accessControl": "READ_WRITE",
            "enableFullLogging": True,
            "order": next_order,
            "rank": 7,
            "predefined": False,
            "defaultRule": False,
            "description": f"Created from Azure: {rule_name}",
            "srcIps": azure_rule.get("source_addresses", []),
            "destAddresses": azure_rule.get("destination_addresses", [])
            if azure_rule["rule_type"] == "NetworkRule"
            else azure_rule.get("target_fqdns", []),
            "nwServiceGroups": [{"id": service_group["id"]}],
            "srcIpGroups": src_ip_groups if src_ip_groups else [],
        }

        # Remove empty fields to avoid payload rejection
        payload = {k: v for k, v in payload.items() if v}

        # Send the POST request
        url = f"{ZIA_API_URL}/firewallFilteringRules"
        headers = {"Cookie": zia_token, "Content-Type": "application/json"}

        try:
            logging.info(f"Creating ZIA Firewall Rule: {rule_name}")
            response = requests.post(url, headers=headers, json=payload)

            # Log request and response for debugging
            logging.debug(f"Request Headers: {response.request.headers}")
            logging.debug(f"Request Body: {response.request.body}")
            logging.debug(f"Response Status Code: {response.status_code}")
            logging.debug(f"Response Content: {response.text}")

            response.raise_for_status()
            new_rules.append(rule_name)
            next_order += 1  # Increment order for the next rule
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:  # Handle rate limiting
                retry_after = int(response.headers.get("Retry-After", 1))
                logging.warning(f"Rate limit hit. Retrying after {retry_after} seconds...")
                time.sleep(retry_after)
            else:
                logging.error(f"HTTPError creating ZIA Firewall Rule '{rule_name}': {response.text}")
        except requests.exceptions.RequestException as e:
            logging.error(f"RequestException creating ZIA Firewall Rule '{rule_name}': {e}")

    logging.info(f"Created {len(new_rules)} new ZIA Firewall Rules.")
    return new_rules

# Activate ZIA Changes
def activate_zia_changes(zia_token):
    """
    Activate pending changes in ZIA.
    """
    url = f"{ZIA_API_URL}/status/activate"
    headers = {"Cookie": zia_token, "Content-Type": "application/json"}
    payload = {"activate": True}

    try:
        logging.info("Activating ZIA changes...")
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        logging.info("ZIA changes activated successfully.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error activating ZIA changes: {e}")

# Main
def main():
    # Step 1: Authenticate to Azure and Zscaler
    credential = authenticate_to_azure()
    zia_token = zscaler_authenticate()

    # Step 2: Fetch Azure IP groups and firewall rules
    logging.info("Fetching Azure IP Groups and Firewall Rules...")
    azure_ip_groups = fetch_azure_ip_groups(credential)
    azure_firewall_rules = fetch_firewall_rules(credential)

    # Step 3: Optionally filter Azure firewall rules by rule name
    if TARGET_AZURE_RULE_NAME:
        logging.info(f"Filtering Azure Firewall Rules for TARGET_AZURE_RULE_NAME: {TARGET_AZURE_RULE_NAME}")
        azure_firewall_rules = [
            rule for rule in azure_firewall_rules if rule["rule_name"] == TARGET_AZURE_RULE_NAME
        ]
        if not azure_firewall_rules:
            logging.warning(f"No matching Azure rules found for TARGET_AZURE_RULE_NAME: {TARGET_AZURE_RULE_NAME}")
            return
        else:
            logging.info(f"Filtered Azure rule(s): {json.dumps(azure_firewall_rules, indent=4)}")

    # Step 4: Fetch existing ZIA data
    logging.info("Fetching Zscaler IP Source Groups, Firewall Rules, Network Services, and Service Groups...")
    zia_source_groups = get_zscaler_ip_source_groups(zia_token)
    zia_firewall_rules = get_zscaler_firewall_rules(zia_token)
    zia_network_services = get_zscaler_network_services(zia_token)
    zia_service_groups = get_zscaler_network_service_groups(zia_token)

    # Step 5: Export fetched data to JSON files for debugging and persistence
    logging.info("Exporting fetched data to JSON files...")
    export_to_json(azure_ip_groups, IP_GROUPS_FILE)
    export_to_json(azure_firewall_rules, FIREWALL_RULES_FILE)
    export_to_json(zia_source_groups, ZIA_SOURCE_GROUPS_FILE)
    export_to_json(zia_firewall_rules, "zscaler_firewall_rules.json")
    export_to_json(zia_network_services, "zscaler_network_services.json")
    export_to_json(zia_service_groups, "zscaler_network_service_groups.json")
    logging.info("Data export completed.")

    # Step 6: Create missing ZIA IP groups
    if prompt_confirmation("Obtained all data. Continue with attempting to create Zscaler objects?"):
        logging.info("Creating missing ZIA IP Source Groups...")
        zia_source_groups = create_zia_ip_source_groups(azure_ip_groups, zia_source_groups, zia_token)

    # Step 7: Create missing ZIA network services
    logging.info("Creating missing ZIA Network Services...")

    azure_protocols = []
    for rule in azure_firewall_rules:
        if rule["rule_type"] == "ApplicationRule" and "protocols" in rule:
            azure_protocols.extend(rule["protocols"])
        elif rule["rule_type"] == "NetworkRule" and "destination_ports" in rule:
            for port in rule["destination_ports"]:
                azure_protocols.append({"protocol": "TCP", "port": int(port)})  # Assuming TCP for NetworkRule

    zia_network_services = create_zia_network_services(azure_protocols, zia_network_services, zia_token)

    # Separate processing for ApplicationRule and NetworkRule
    azure_protocols = []
    for rule in azure_firewall_rules:
        if rule["rule_type"] == "ApplicationRule" and "protocols" in rule:
            azure_protocols.extend(rule["protocols"])
        elif rule["rule_type"] == "NetworkRule" and "destination_ports" in rule:
            for port in rule["destination_ports"]:
                azure_protocols.append({"protocol": "TCP", "port": int(port)})  # Assuming all NetworkRules are TCP

    # Pass both ApplicationRule and NetworkRule data
    zia_network_services = create_zia_network_services(azure_protocols, zia_network_services, zia_token)

    # Step 8: Create missing ZIA service groups
    logging.info("Creating missing ZIA Service Groups...")

    for rule in azure_firewall_rules:
        # Collect services for this rule from created ZIA network services
        services = []
        if rule["rule_type"] == "ApplicationRule" and "protocols" in rule:
            for protocol in rule["protocols"]:
                service_name = f"AzureFw_{protocol['protocol'].upper()}_{protocol['port']}"
                service_id = next(
                    (service["id"] for service in zia_network_services if service["name"] == service_name), None
                )
                if service_id:
                    services.append({"id": service_id})
        elif rule["rule_type"] == "NetworkRule" and "destination_ports" in rule:
            for port in rule["destination_ports"]:
                service_name = f"AzureFw_TCP_{port}"
                service_id = next(
                    (service["id"] for service in zia_network_services if service["name"] == service_name), None
                )
                if service_id:
                    services.append({"id": service_id})

        if services:
            create_zia_network_service_groups(rule["rule_name"], services, zia_service_groups, zia_token)

    # Step 9: Create missing ZIA firewall rules
    logging.info("Creating missing ZIA Firewall Rules...")
    created_firewall_rules = create_zia_firewall_rules(
        azure_firewall_rules, zia_firewall_rules, zia_source_groups, zia_service_groups, zia_token
    )

    # Step 10: Activate ZIA changes if new firewall rules were created
    if created_firewall_rules:
        logging.info("Activating ZIA changes...")
        activate_zia_changes(zia_token)

if __name__ == "__main__":
    main()
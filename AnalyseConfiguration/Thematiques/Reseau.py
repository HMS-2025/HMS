import yaml
import os
import paramiko
from GenerationRapport.GenerationRapport import generate_html_report

# Execute an SSH command on the remote server and return the result as a list of lines.
def execute_ssh_command(server, command):
    stdin, stdout, stderr = server.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Compare detected values with reference data. For rule R78, ensure no slice has 50% or more of the services.
def check_compliance(rule_id, detected_values, reference_data):
    if rule_id == "R78":
        slice_to_services = detected_values.get("slice_to_services", {})
        total_services = sum(len(services) for services in slice_to_services.values())
        
        # No service detected
        if total_services == 0:
            return {
                "apply": False,
                "status": "Non-Compliant",
                "expected_elements": "At least one service should be detected",
                "detected_elements": "No service detected"
            }
        
        # Calculate maximum percentage for any slice
        max_percentage = max((len(services) / total_services) * 100 for services in slice_to_services.values())
        
        # The system is compliant if no slice contains 50% or more of the services
        compliant = max_percentage < 50.0
        
        return {
            "apply": compliant,
            "status": "Compliant" if compliant else "Non-Compliant",
            "expected_elements": "No slice should contain 50% or more of the services",
            "detected_elements": slice_to_services  # returns the dictionary for a clean YAML presentation
        }
    if rule_id == 'R67' : 
        # For other rules, proceed with the default comparison.
        expected_values = reference_data.get(rule_id, {}).get("expected", {}).get("pam_rules",[])
        detected = detected_values.get('pam_rules', [])
        difference = []
        for rule in expected_values : 
            if rule not in detected : 
                difference.append(rule)
        
        if len(difference) != 0 : 
            return {
                "apply": False ,
                "status": "Non-Compliant",
                "expected_elements": expected_values or "None",
                "difference": difference or "None"
            }
        else :
            return {
                "apply": True ,
                "status": "Compliant",
                "expected_elements": expected_values or "None",
                "difference": difference or "None"
            } 


    # For other rules, proceed with the default comparison.
    expected_values = reference_data.get(rule_id, {}).get("expected", {})
    expected_values_list = []
    
    if isinstance(expected_values, dict):
        for key, value in expected_values.items():
            if isinstance(value, list):
                expected_values_list.extend(value)
            else:
                expected_values_list.append(value)
    elif isinstance(expected_values, list):
        expected_values_list = expected_values
    
    return {
        "apply": detected_values == expected_values,
        "status": "Compliant" if detected_values == expected_values else "Non-Compliant",
        "expected_elements": expected_values or "None",
        "detected_elements": detected_values or "None"
    }

# Check IPv4 configuration via sysctl on Ubuntu.
def check_ipv4_configuration(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = "sysctl net.ipv4"
        results = {}
        for line in execute_ssh_command(server, command):
            if '=' in line:
                key, value = line.split('=', 1)
                results[key.strip()] = value.strip()
        return results
    else:
        print(f"[check_ipv4_configuration] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); IPv4 configuration check skipped.")
        return {}

# Check if IPv6 is disabled via sysctl on Ubuntu.
def disable_ipv6(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = "sysctl -a | grep 'net.ipv6.conf.*.disable_ipv6'"
        result = {}
        for line in execute_ssh_command(server, command):
            if '=' in line:
                key, value = line.split('=', 1)
                result[key.strip()] = value.strip()
        return result
    else:
        print(f"[disable_ipv6] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); IPv6 disable check skipped.")
        return {}

# List running services on Ubuntu.
def harden_exposed_services(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = "systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'"
        return {"running_services": execute_ssh_command(server, command)}
    else:
        print(f"[harden_exposed_services] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); running services not retrieved.")
        return {"running_services": []}

# Check SSH PAM configuration on Ubuntu.
def secure_remote_authentication_pam(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = "grep -E '^(auth|account|password|session)' /etc/pam.d/common-auth | awk '{$1=$1};1'"
        return {"pam_rules": execute_ssh_command(server, command)}
    else:
        print(f"[secure_remote_authentication_pam] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); PAM rules not retrieved.")
        return {"pam_rules": []}

# Retrieve network interfaces and their IP addresses on Ubuntu.
def get_interfaces_with_ips(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = "ip -o addr show"
        interfaces = {}
        for line in execute_ssh_command(server, command):
            parts = line.split()
            if len(parts) > 3:
                iface = parts[1]
                ip = parts[3].split('/')[0]
                if iface not in interfaces:
                    interfaces[iface] = {"ipv4": None, "ipv6": None}
                interfaces[iface]["ipv6" if ':' in ip else "ipv4"] = ip
        return interfaces
    else:
        print(f"[get_interfaces_with_ips] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); network interfaces not retrieved.")
        return {}

# Check service isolation by grouping services by their systemd slice on Ubuntu.
def check_services_isolation(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        list_command = "systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'"
        services = execute_ssh_command(server, list_command)
        slice_to_services = {}
        
        for service in services:
            slice_command = f"systemctl show {service} -p Slice"
            slice_output = execute_ssh_command(server, slice_command)
            slice_value = "unknown"
            if slice_output:
                line = slice_output[0]
                if "=" in line:
                    _, slice_value = line.split("=", 1)
                    slice_value = slice_value.strip()
            if slice_value not in slice_to_services:
                slice_to_services[slice_value] = []
            slice_to_services[slice_value].append(service)
        
        return {
            "slice_to_services": slice_to_services,
        }
    else:
        print(f"[check_services_isolation] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); service isolation check skipped.")
        return {"slice_to_services": {}}

# Perform network analysis and generate a compliance report based on defined rules.
def analyse_reseau(server, niveau, reference_data=None, os_info=None):
    if reference_data is None:
        reference_data = {}
    
    report = {}
    rules = {
        "min": {
            "R80": (get_interfaces_with_ips, "Check network interfaces with IP"),
        },
        "moyen": {
            "R12": (check_ipv4_configuration, "Configure IPv4 options (manual modifications required)"),
            "R13": (disable_ipv6, "Disable IPv6 (manual modifications required)"),
            "R79": (harden_exposed_services, "Harden exposed services (manual modifications required)"),
            "R67": (secure_remote_authentication_pam, "Secure remote authentication with PAM"),
            "R81": (get_interfaces_with_ips, "Verify restricted interfaces (R81 same as R80)")
        },
        "renforce": {
            "R78": (check_services_isolation, "Isolate network services: verify services are distributed into distinct slices")
        }
    }
    
    if niveau in rules:
        for rule_id, (function, description) in rules[niveau].items():
            print(f"-> Checking rule {rule_id} # {description}")
            detected_values = function(server, os_info)
            report[rule_id] = check_compliance(rule_id, detected_values, reference_data)
    
    save_yaml_report(report, f"analyse_{niveau}.yml", rules, niveau)
    yaml_path = f"GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    html_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.html"
    compliance_percentage = (sum(1 for r in report.values() if r["status"] == "Compliant") / len(report) * 100) if report else 0
    print(f"\nCompliance rate for level {niveau.upper()} (Network) : {compliance_percentage:.2f}%")
    generate_html_report(yaml_path, html_path, niveau)

# Save the analysis report to a YAML file.
def save_yaml_report(data, output_file, rules, niveau):
    if not data:
        return
    
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    
    with open(output_path, "a", encoding="utf-8") as file:
        file.write("network:\n")
        for rule_id, content in data.items():
            comment = rules[niveau].get(rule_id, (None, ""))[1]
            file.write(f"  {rule_id}:  # {comment}\n")
            yaml_content = yaml.safe_dump(
                content, default_flow_style=False, allow_unicode=True, indent=4, sort_keys=False
            )
            indented_yaml = "\n".join(["    " + line for line in yaml_content.split("\n") if line.strip()])
            file.write(indented_yaml + "\n")
        file.write("\n")
    
    print(f"Report generated : {output_path}")


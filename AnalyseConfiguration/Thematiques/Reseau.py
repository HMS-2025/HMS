import yaml
import os
import paramiko
from GenerationRapport.GenerationRapport import generate_html_report

# Executes an SSH command on the remote server and returns the result as a list of lines.
def execute_ssh_command(server, command):
    stdin, stdout, stderr = server.exec_command(command)
    return list(filter(None, stdout.read().decode().strip().split("\n")))

# Compare detected values with reference data.
def check_compliance(rule_id, detected_values, reference_data):
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

# Check IPv4 configuration via sysctl.
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

# Check IPv6 disable configuration via sysctl.
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

# List running services.
def harden_exposed_services(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = "systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'"
        return {"running_services": execute_ssh_command(server, command)}
    else:
        print(f"[harden_exposed_services] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); running services not retrieved.")
        return {"running_services": []}

# Check certain PAM rules in /etc/pam.d/sshd.
def secure_remote_authentication_pam(server, os_info):
    if os_info and os_info.get("distro", "").lower() == "ubuntu":
        command = "grep -E '^(auth|account|password|session)' /etc/pam.d/sshd | awk '{$1=$1};1'"
        return {"pam_rules": execute_ssh_command(server, command)}
    else:
        print(f"[secure_remote_authentication_pam] Non-Ubuntu OS ({os_info.get('distro', 'unknown') if os_info else 'unknown'}); PAM rules not retrieved.")
        return {"pam_rules": []}

# Retrieve the list of network interfaces and their IP addresses.
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

# Network analysis and report generation.
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

    html_yaml_path = f"GenerationRapport/RapportAnalyse/RapportHTML/analyse_{niveau}.yml"

    if os.path.exists(html_yaml_path):
        os.remove(html_yaml_path)

# Save the analysis report in a YAML file.
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

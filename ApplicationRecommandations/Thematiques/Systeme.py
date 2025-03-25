import yaml

#=========== Global ==========
application_moyen = "./GenerationRapport/RapportApplication/application_moyen.yml"
analyse_moyen = "./GenerationRapport/RapportAnalyse/analyse_moyen.yml"

def execute_ssh_command(client, command):
    """Execute an SSH command and return output and error."""
    stdin, stdout, stderr = client.exec_command(command)
    output = list(filter(None, stdout.read().decode().strip().split("\n")))
    error = stderr.read().decode().strip()
    return output, error

def update(application_file, analyse_file, thematique, rule):
    with open(application_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    data[thematique][rule]['apply'] = False
    data[thematique][rule]['status'] = 'Compliant'
    with open(application_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

    with open(analyse_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)
    data[thematique][rule]['apply'] = True
    data[thematique][rule]['status'] = 'Compliant'
    with open(analyse_file, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)

def update_report(level, thematique, rule):
    if level == 'moyen':
        update(application_moyen, analyse_moyen, thematique, rule)

def apply_r8(client, report):
    r8_data = report.get("R8", {})
    if not r8_data.get("apply", False):
        print("- R8: No action required.")
        return "Compliant"

    print("- Applying memory security options at boot")
    grub_files = ["/etc/default/grub.d/50-cloudimg-settings.cfg"]
    grub_file = None

    # Locate the GRUB configuration file
    for file in grub_files:
        output, _ = execute_ssh_command(client, f"test -f {file} && echo 'FOUND' || echo 'MISSING'")
        if output and output[0] == "FOUND":
            grub_file = file
            break

    if not grub_file:
        print("Error: GRUB configuration file not found.")
        return "Non-Compliant"

    # Backup the existing GRUB file
    grub_backup = f"{grub_file}.backup"
    execute_ssh_command(client, f"sudo cp -n {grub_file} {grub_backup}")
    print(f"Backup created: {grub_backup}")

    # Read expected elements and apply them
    detected_elements = r8_data.get("detected_elements", [])
    expected_elements = r8_data.get("expected_elements", [])
    if not expected_elements:
        print("Error: No expected elements defined for R8.")
        return "Non-Compliant"

    for param in expected_elements:
        key, value = param.split("=", 1)
        if key in detected_elements:
            # Update existing parameter value
            execute_ssh_command(client, f"sudo sed -i 's|{key}=[^ ]*|{key}={value}|g' {grub_file}")
        else:
            # Add missing parameter if not already present
            execute_ssh_command(client, f"sudo grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' {grub_file} || echo 'GRUB_CMDLINE_LINUX_DEFAULT=\"\"' | sudo tee -a {grub_file} > /dev/null")
            execute_ssh_command(client, f"sudo sed -i '/GRUB_CMDLINE_LINUX_DEFAULT=/s|\"$| {key}={value}\"|' {grub_file}")
    # Update GRUB settings
    execute_ssh_command(client, "sudo update-grub")
    print("GRUB configuration updated successfully.")

    # Update the report to reflect the changes
    update_report('moyen', 'system', 'R8')
    print("Report updated for R8.")

def apply_r9(client, report):
    
    # Define the reference expected kernel settings
    expected_elements = {
        "kernel.dmesg_restrict": "1",
        "kernel.kptr_restrict": "2",
        "kernel.pid_max": "65536",
        "kernel.perf_cpu_time_max_percent": "1",
        "kernel.perf_event_max_sample_rate": "1",
        "kernel.perf_event_paranoid": "2",
        "kernel.randomize_va_space": "2",
        "kernel.sysrq": "0",
        "kernel.unprivileged_bpf_disabled": "1",
        "kernel.panic_on_oops": "1"
    }

    r9_data = report.get("R9", {})
    if not r9_data.get("apply", False):
        print("- R9: No action required.")
        return "Compliant"

    print("- Applying kernel security settings")
    sysctl_file = "/etc/sysctl.conf"
    backup_file = f"{sysctl_file}.backup"

    # Create a backup of the sysctl file
    execute_ssh_command(client, f"sudo cp -n {sysctl_file} {backup_file}")
    print(f"Backup created: {backup_file}")

    # Load detected values from the report
    detected_elements = r9_data.get("detected", {})

    # Apply each expected kernel parameter
    for kernel_param, expected_value in expected_elements.items():
        # Check if the parameter is detected and matches the expected value
        detected_value = detected_elements.get(kernel_param)
        if detected_value != expected_value:
            print(f"- Setting {kernel_param} to {expected_value} (detected: {detected_value})")
            execute_ssh_command(client, f"sudo sed -i '/^{kernel_param}/d' {sysctl_file}")  # Remove existing entry if present
            execute_ssh_command(client, f"echo '{kernel_param} = {expected_value}' | sudo tee -a {sysctl_file} > /dev/null")

    # Reload the sysctl settings
    execute_ssh_command(client, "sudo sysctl -p")
    print("Kernel security settings applied successfully.")

    # Update the report to reflect the changes
    update_report('moyen', 'system', 'R9')
    print("Report updated for R9.")

def apply_r11(client, report):
    # Define the reference expected setting for Yama LSM
    expected_elements = {
        "kernel.yama.ptrace_scope": "1"
    }

    r11_data = report.get("R11", {})
    if not r11_data.get("apply", False):
        print("- R11: No action required.")
        return "Compliant"

    print("- Applying Yama LSM settings")
    sysctl_file = "/etc/sysctl.conf"
    backup_file = f"{sysctl_file}.backup"

    # Create a backup of the sysctl file
    execute_ssh_command(client, f"sudo cp -n {sysctl_file} {backup_file}")
    print(f"Backup created: {backup_file}")

    # Load detected values from the report
    detected_elements = r11_data.get("detected", {})

    # Apply the Yama LSM parameter if needed
    for kernel_param, expected_value in expected_elements.items():
        detected_value = detected_elements.get(kernel_param)
        if detected_value != expected_value:
            print(f"- Setting {kernel_param} to {expected_value} (detected: {detected_value})")
            execute_ssh_command(client, f"sudo sed -i '/^{kernel_param}/d' {sysctl_file}")  # Remove existing entry if present
            execute_ssh_command(client, f"echo '{kernel_param} = {expected_value}' | sudo tee -a {sysctl_file} > /dev/null")

    # Reload the sysctl settings
    execute_ssh_command(client, "sudo sysctl -p")
    print("Yama LSM setting applied successfully.")

    # Update the report to reflect the changes
    update_report('moyen', 'system', 'R11')
    print("Report updated for R11.")

def apply_r14(client, report):
    # Define the reference expected filesystem security settings
    expected_elements = {
        "fs.suid_dumpable": "0",
        "fs.protected_fifos": "2",
        "fs.protected_regular": "2",
        "fs.protected_symlinks": "1",
        "fs.protected_hardlinks": "1"
    }

    r14_data = report.get("R14", {})
    if not r14_data.get("apply", False):
        print("- R14: No action required.")
        return "Compliant"

    print("- Applying filesystem security settings")
    sysctl_file = "/etc/sysctl.conf"
    backup_file = f"{sysctl_file}.backup"

    # Create a backup of the sysctl file
    execute_ssh_command(client, f"sudo cp -n {sysctl_file} {backup_file}")
    print(f"Backup created: {backup_file}")

    # Load detected values from the report
    detected_elements = r14_data.get("detected", {})

    # Apply each expected fs parameter
    for fs_param, expected_value in expected_elements.items():
        detected_value = detected_elements.get(fs_param)
        if detected_value != expected_value:
            print(f"- Setting {fs_param} to {expected_value} (detected: {detected_value})")
            execute_ssh_command(client, f"sudo sed -i '/^{fs_param}/d' {sysctl_file}")  # Remove existing entry if present
            execute_ssh_command(client, f"echo '{fs_param} = {expected_value}' | sudo tee -a {sysctl_file} > /dev/null")

    # Reload the sysctl settings
    execute_ssh_command(client, "sudo sysctl -p")
    print("Filesystem security settings applied successfully.")

    # Update the report to reflect the changes
    update_report('moyen', 'system', 'R14')
    print("Report updated for R14.")


#=========== Main ==========
def apply_system(client, niveau, report_data):
    if report_data is None:
        report_data = {}

    apply_data = report_data.get("system", None)
    if apply_data is None:
        return

    rules = {
        "moyen": {
            "R8": (apply_r8, "Configurer les options de sécurité mémoire au démarrage"),
            "R9": (apply_r9, "Configurer les paramètres de sécurité du noyau"),
            "R11": (apply_r11, "Activer et configurer Yama LSM"),
            "R14": (apply_r14, "Configurer la sécurité des systèmes de fichiers"),
        }
    }

    if niveau in rules:
        for rule_id, (function, comment) in rules[niveau].items():
            if apply_data.get(rule_id, {}).get("apply", False):
                print(f"-> Applying rule {rule_id}: {comment}")
                function(client, apply_data)

    print(f"\n- Corrections applied - system - Level {niveau.upper()}")

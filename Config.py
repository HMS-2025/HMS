#-------------DEPENDENCIES----------------# 

import paramiko
import yaml
import os
import socket
import subprocess

#-------------UTILITY FUNCTIONS-----------------# 

# Load configuration from the YAML file
def load_config(yaml_file):
    try:
        with open(yaml_file, "r") as file:
            config = yaml.safe_load(file)
        return config.get("ssh", {})
    except Exception as e:
        print(f"Error loading YAML file: {e}")
        return {}

# Check if the host is reachable via ping
def is_host_reachable(hostname):
    try:
        # Ping command adapted to OS
        ping_cmd = ["ping", "-c", "1", "-W", "1", hostname] if os.name != "nt" else ["ping", "-n", "1", hostname]
        result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception as e:
        print(f"Error checking host reachability: {e}")
        return False

# Check if the port is open
def is_port_open(hostname, port, timeout=3):
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

# Connect to SSH
def ssh_connect(hostname, port, username, key_path, passphrase=None):
    if not key_path or not os.path.isfile(key_path):
        print(f"Error: SSH key not found at the specified path: {key_path}")
        return None

    if not isinstance(port, int) or not (1 <= port <= 65535):
        print("Error: The port must be an integer between 1 and 65535.")
        return None
    
    if not is_host_reachable(hostname):
        print(f"Error: Host {hostname} is unreachable.")
        return None

    if not is_port_open(hostname, port):
        print(f"Error: Port {port} on {hostname} is closed or unreachable.")
        return None

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        key = None
        key_classes = [paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey, paramiko.Ed25519Key]

        for key_class in key_classes:
            try:
                key = key_class.from_private_key_file(key_path, password=passphrase)
                break
            except paramiko.ssh_exception.SSHException:
                continue  

        if key is None:
            raise ValueError("Unsupported SSH key format or invalid file.")

        key_size = key.get_bits()
        print(f"SSH key size used: {key_size} bits")

        # Check minimum security standards for the key size
        if isinstance(key, paramiko.RSAKey) and key_size < 2048:
            print("Warning: The RSA key used is smaller than 2048 bits, which is considered insecure.")
        elif isinstance(key, paramiko.ECDSAKey) and key_size < 256:
            print("Warning: The ECDSA key used is smaller than 256 bits, which is considered insecure.")
        elif isinstance(key, paramiko.DSSKey) and key_size < 1024:
            print("Warning: The DSS key used is smaller than 1024 bits, which is considered insecure.")

        client.connect(hostname, port=port, username=username, pkey=key)
        print("SSH connection successful!")
        return client
    except paramiko.AuthenticationException:
        print("Error: Authentication failed. Check your credentials.")
    except paramiko.SSHException as e:
        print(f"SSH error: {e}")
    except Exception as e:
        print(f"SSH connection error: {e}")
    return None

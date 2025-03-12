from Config import load_config, ssh_connect
import os
import subprocess
import shutil
import paramiko
import yaml

# --- Management of the rockyou wordlist ---

def get_rockyou_wordlist_path():
    wordlist = "/usr/share/wordlists/rockyou.txt"
    gz_wordlist = wordlist + ".gz"
    if os.path.exists(wordlist):
        return wordlist
    elif os.path.exists(gz_wordlist):
        print("[John] Decompressing rockyou.txt.gz to rockyou.txt")
        try:
            subprocess.run(["gunzip", "-k", gz_wordlist], check=True)
            if os.path.exists(wordlist):
                return wordlist
            else:
                print("[John] Decompression failed, rockyou.txt was not created.")
                return None
        except subprocess.CalledProcessError as e:
            print(f"[John] Error during decompression of rockyou.txt.gz: {e}")
            return None
    else:
        print("[John] rockyou.txt does not exist and rockyou.txt.gz was not found.")
        return None

# --- Installation and usage of John The Ripper ---

def is_john_installed():
    """
    Checks only if the 'john' directory exists in the current folder
    and that the expected binary is present in john/run.
    """
    john_binary = os.path.join(os.getcwd(), "john", "run", "john")
    return os.path.exists(john_binary)

def install_john():
    if os.path.exists("john"):
        john_binary = os.path.join(os.getcwd(), "john", "run", "john")
        if os.path.exists(john_binary):
            print("[John] The 'john' directory is already present in the current folder.")
            return
        else:
            print("[John] The 'john' directory already exists but does not contain a usable installation.")
            print("[John] Please remove or rename the 'john' directory to reinstall.")
            return

    print("[John] Installing John The Ripper...")
    try:
        subprocess.run("sudo apt update", shell=True, check=True)
        subprocess.run("sudo apt install -y build-essential libssl-dev", shell=True, check=True)
        subprocess.run("git clone https://github.com/openwall/john.git", shell=True, check=True)
        src_dir = os.path.join(os.getcwd(), "john", "src")
        subprocess.run("./configure", shell=True, check=True, cwd=src_dir)
        subprocess.run("make -sj$(nproc)", shell=True, check=True, cwd=src_dir)
        # No symbolic link is created since verification is done directly on the current directory.
        print("[John] Installation successful!")
    except subprocess.CalledProcessError as e:
        print(f"[John] Installation failed: {e}")

def retrieve_hash_files(ssh_client, remote_path, local_path):
    try:
        stdin, stdout, stderr = ssh_client.exec_command(f"sudo cat {remote_path}")
        file_content = stdout.read()
        print(file_content)
        with open(local_path, "wb") as local_file:
            local_file.write(file_content)
        print(f"File retrieved: {remote_path} → {local_path}")
    except Exception as e:
        print(f"Error retrieving file {remote_path}: {e}")

def save_hashes_from_shadow(input_file, output_file):
    try:
        with open(input_file, "r") as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file {input_file}: {e}")
        return
    lines = content.strip().splitlines()
    try:
        with open(output_file, "w") as out:
            for line in lines:
                if not line.strip():
                    continue
                fields = line.split(":")
                if len(fields) < 2:
                    continue
                username = fields[0]
                passwd = fields[1]
                if passwd.startswith("$"):
                    out.write(f"{username}:{passwd}\n")
        print(f"Hashes saved in file {output_file}.")
    except Exception as e:
        print(f"Error writing to file {output_file}: {e}")

def remove_john_pot():
    """Deletes the john.pot file in the john/run folder, if it exists."""
    john_run_dir = os.path.join(os.getcwd(), "john", "run")
    pot_path = os.path.join(john_run_dir, "john.pot")
    if os.path.exists(pot_path):
        try:
            os.remove(pot_path)
            print("[John] john.pot file deleted.")
        except Exception as e:
            print(f"[John] Error deleting john.pot: {e}")

def run_john_dictionary(hash_file):
    remove_john_pot()
    abs_hash_file = os.path.abspath(hash_file)
    print(f"[John] Launching dictionary attack on: {abs_hash_file}")
    wordlist_path = get_rockyou_wordlist_path()
    if not wordlist_path:
        print("[John] Aborting attack because wordlist was not found.")
        return
    john_run_dir = os.path.join(os.getcwd(), "john", "run")
    john_binary = os.path.join(john_run_dir, "john")
    command = [john_binary, "--wordlist=" + wordlist_path, "--format=sha512crypt", abs_hash_file]
    try:
        subprocess.run(command, check=True, cwd=john_run_dir)
        print("[John] Displaying results:")
        subprocess.run([john_binary, "--show", abs_hash_file], check=True, cwd=john_run_dir)
    except FileNotFoundError:
        print("[John] The 'john' binary was not found. Please check your John The Ripper installation.")
    except subprocess.CalledProcessError as e:
        print(f"[John] Error during dictionary attack: {e}")

def run_john_rules(hash_file):
    remove_john_pot()
    abs_hash_file = os.path.abspath(hash_file)
    print(f"[John] Launching attack with advanced rules on: {abs_hash_file}")
    wordlist_path = get_rockyou_wordlist_path()
    if not wordlist_path:
        print("[John] Aborting attack because wordlist was not found.")
        return
    john_run_dir = os.path.join(os.getcwd(), "john", "run")
    john_binary = os.path.join(john_run_dir, "john")
    command = [john_binary, "--wordlist=" + wordlist_path, "--rules=Jumbo", "--format=sha512crypt", abs_hash_file]
    try:
        subprocess.run(command, check=True, cwd=john_run_dir)
        print("[John] Displaying results:")
        subprocess.run([john_binary, "--show", abs_hash_file], check=True, cwd=john_run_dir)
    except FileNotFoundError:
        print("[John] The 'john' binary was not found. Please check your John The Ripper installation.")
    except subprocess.CalledProcessError as e:
        print(f"[John] Error during advanced rules attack: {e}")

def run_john_generated(hash_file):
    remove_john_pot()
    abs_hash_file = os.path.abspath(hash_file)
    print(f"[John] Launching attack with generated wordlist on: {abs_hash_file}")
    generated_wordlist = os.path.join(os.getcwd(), "liste générée")
    if not os.path.exists(generated_wordlist):
        print("[John] The generated wordlist does not exist. Please generate it first (option 4).")
        return
    john_run_dir = os.path.join(os.getcwd(), "john", "run")
    john_binary = os.path.join(john_run_dir, "john")
    command = [john_binary, "--wordlist=" + generated_wordlist, "--format=sha512crypt", abs_hash_file]
    try:
        subprocess.run(command, check=True, cwd=john_run_dir)
        print("[John] Displaying results:")
        subprocess.run([john_binary, "--show", abs_hash_file], check=True, cwd=john_run_dir)
    except FileNotFoundError:
        print("[John] The 'john' binary was not found. Please check your John The Ripper installation.")
    except subprocess.CalledProcessError as e:
        print(f"[John] Error during attack with generated wordlist: {e}")

# --- Generation of simple "genetic" variants ---
# Defined structure: variants with or without an initial capital letter, then concatenation of the word, the year,
# and optionally a special character as prefix or suffix.

def generate_partial_variants(word):
    mapping = {'a': '@', 'i': '1', 's': '$', 'o': '0', 'e': '3'}
    def helper(s):
        if not s:
            return [""]
        first = s[0]
        rest = s[1:]
        variants_rest = helper(rest)
        result = []
        if first.lower() in mapping:
            for variant in variants_rest:
                result.append(first + variant)
            replacement = mapping[first.lower()]
            if first.isupper():
                replacement = replacement.upper()
            for variant in variants_rest:
                result.append(replacement + variant)
        else:
            for variant in variants_rest:
                result.append(first + variant)
        return result
    return list(set(helper(word)))

def generate_full_variants(word, start_year=2000, end_year=2030):
    # Base variants with mutations.
    base_variants = generate_partial_variants(word)
    # Case variants: the word as-is and with the first letter capitalized.
    case_variants = set()
    for variant in base_variants:
        case_variants.add(variant.lower())
        case_variants.add(variant.capitalize())
    full_variants = set(case_variants)
    # Restricted special characters.
    special_chars = ["@", "#", "_", "!"]
    for variant in case_variants:
        for year in range(start_year, end_year + 1):
            y = str(year)
            for special in special_chars:
                full_variants.add(variant + y + special)
                full_variants.add(y + special + variant)
    return list(full_variants)

def generate_wordlist():
    """
    Asks the user for a list of words or accounts (separated by spaces).
    If an element contains ":", both parts are added.
    Moreover, if the "cassage" file exists, it extracts the usernames (the part before ":").
    Then, for each word, it generates the complete simple variants.
    The result is saved in the "liste générée" file in the current directory.
    """
    words_input = input("Enter a list of words or accounts (separated by spaces): ")
    words_raw = words_input.split()
    words = []
    for w in words_raw:
        if ":" in w:
            parts = w.split(":")
            words.append(parts[0])
            words.append(parts[1])
        else:
            words.append(w)
    cassage_path = os.path.join(os.getcwd(), "cassage")
    if os.path.exists(cassage_path):
        with open(cassage_path, "r") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    username = line.split(":")[0]
                    words.append(username)
    words = list(set(words))
    all_variants = set()
    for word in words:
        variants = generate_full_variants(word)
        all_variants.update(variants)
    output_file = os.path.join(os.getcwd(), "liste générée")
    try:
        with open(output_file, "w") as f:
            for variant in sorted(all_variants):
                f.write(variant + "\n")
        print(f"Wordlist generated with {len(all_variants)} entries in file '{output_file}'.")
    except Exception as e:
        print(f"Error writing the wordlist: {e}")

# --- Option to crack using the generated wordlist ---
# (Note: The function run_john_generated is defined earlier and redefined here to correspond to option 5.)

def run_john_generated(hash_file):
    remove_john_pot()
    abs_hash_file = os.path.abspath(hash_file)
    print(f"[John] Launching attack with generated wordlist on: {abs_hash_file}")
    generated_wordlist = os.path.join(os.getcwd(), "liste générée")
    if not os.path.exists(generated_wordlist):
        print("[John] The generated wordlist does not exist. Please generate it first (option 4).")
        return
    john_run_dir = os.path.join(os.getcwd(), "john", "run")
    john_binary = os.path.join(john_run_dir, "john")
    command = [john_binary, "--wordlist=" + generated_wordlist, "--format=sha512crypt", abs_hash_file]
    try:
        subprocess.run(command, check=True, cwd=john_run_dir)
        print("[John] Displaying results:")
        subprocess.run([john_binary, "--show", abs_hash_file], check=True, cwd=john_run_dir)
    except FileNotFoundError:
        print("[John] The 'john' binary was not found. Please check your John The Ripper installation.")
    except subprocess.CalledProcessError as e:
        print(f"[John] Error during attack with generated wordlist: {e}")

# --- Interactive menus ---

def menu_crack():
    cassage_path = os.path.join(os.getcwd(), "cassage")
    if not os.path.exists("john"):
        print("[John] The 'john' directory is not present in the current folder. Please install it (option 1) before starting the cracking.")
        return
    if not os.path.exists(cassage_path):
        print("[John] The 'cassage' file does not exist. Please first retrieve the shadow file and extract the hashes.")
        return

    while True:
        print("\n=== John The Ripper Cracking Menu ===")
        print("1 - Dictionary attack (rockyou wordlist)")
        print("2 - Attack with advanced rules (rockyou wordlist)")
        print("3 - Attack with generated wordlist")
        print("4 - Return to main menu")
        choice = input("Your choice (1-4): ")

        if choice == "1":
            run_john_dictionary(cassage_path)
        elif choice == "2":
            run_john_rules(cassage_path)
        elif choice == "3":
            run_john_generated(cassage_path)
        elif choice == "4":
            break
        else:
            print("Invalid option. Please try again.")

def menu_principal():
    cassage_path = os.path.join(os.getcwd(), "cassage")
    while True:
        print("\n=== Main Menu ===")
        print("1 - Install John The Ripper")
        print("2 - Retrieve the shadow file (via SSH)")
        print("3 - Crack the hashes (attacks with John, rockyou wordlist)")
        print("4 - Generate a complete wordlist from a list of words")
        print("5 - Crack the hashes with the generated wordlist")
        print("6 - Quit")
        choice = input("Your choice (1-6): ")

        if choice == "1":
            install_john()
        elif choice == "2":
            config = load_config("ssh.yaml")
            if not config:
                print("Invalid configuration")
                continue
            client = ssh_connect(
                hostname=config.get("hostname"),
                port=config.get("port"),
                username=config.get("username"),
                key_path=config.get("key_path"),
                passphrase=config.get("passphrase")
            )
            if client:
                local_shadow_path = os.path.join(os.getcwd(), "shadow")
                retrieve_hash_files(client, "/etc/shadow", local_shadow_path)
                save_hashes_from_shadow(local_shadow_path, cassage_path)
                client.close()
        elif choice == "3":
            menu_crack()
        elif choice == "4":
            generate_wordlist()
        elif choice == "5":
            run_john_generated(cassage_path)
        elif choice == "6":
            print("Goodbye.")
            break
        else:
            print("Invalid option. Please try again.")

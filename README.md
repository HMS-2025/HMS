# Hardening Magic Script (HMS)

## Project Description

**Hardening Magic Script (HMS)** is a Python script (compatible with Python 3.8) designed to audit and harden the security of **Ubuntu servers (version 20.04 LTS and above)** based on the official **ANSSI guidelines** for GNU/Linux systems and OpenSSH configurations.

HMS connects to a remote server via SSH and analyzes its security posture against the ANSSI recommendations. It generates a detailed YAML configuration report and can apply recommended hardening measures — without disrupting production services. 
he tool also includes **risk warnings** for recommendations that may impact live systems.

In addition, HMS offers **behavioral monitoring** over a user-defined period to tailor firewall and SSH restrictions.

HMS retrieves **hashed passwords** from `/etc/shadow` and performs **local password cracking** using **John the Ripper**. 
The goal is to identify weak passwords using smart dictionaries (e.g., cracking `M1cr0$oFT2015!` from the login `microsoft`), without resorting to overly large wordlists.

The script outputs a **customizable YAML configuration file** that documents each proposed change. This YAML can be edited and reused across multiple servers with similar configurations.

**Note:** HMS is designed for **non-disruptive deployments**. Users remain in full control of which actions are applied.

---

## Installation

### Requirements
- Python 3.8 (locally, where the script runs)
- Ubuntu 20.04+ server as target (accessible via SSH)
- Admin access (sudo or root) on the remote server
- SSH access from the local machine
- **John the Ripper** installation via the integrated menu

### Python Dependencies
- `paramiko` (for SSH connection)
- `PyYAML` (for YAML config generation)
- `pyshark` (for network packet analysis)

You can install them with:
```bash
pip install paramiko pyyaml pyshark
```

### Install Steps
1. Clone the repo:
   ```bash
   git clone https://github.com/HMS-2025/HMS.git
   cd HMS
   ```
2. Install dependencies:
    ```bash
    pip install paramiko pyyaml
    ```

## Usage modes

#### Interactive Mode
Launches a menu-driven interface to walk through audit and hardening steps.

```bash
python3 script.py
```

#### Command-line Mode

+ `-m`, `-i`, `-r`                   | Run ANSSI audit at different levels 
+ `--ssh`                            | SSH-focused audit only 
+ `--all`                            | Run all audit types 
+ `--recommendations general/ssh`    | Apply system/SSH recommendations from YAML 
+ `--john`                           | Run full password audit using John 
+ `--john-shadow`                    | Retrieve `/etc/shadow` from the server 
+ `--john-wordlist "<words>"`        | Generate custom wordlist 
+ `--john-crack`                     | Launch John password cracking 

### 🔧 Example Usage

- Full audit:
  ```bash
  python3 script.py --all
  ```

- Password audit with custom wordlist:
  ```bash
  python3 script.py --john-shadow
  python3 script.py --john-wordlist "admin welcome123"
  python3 script.py --john-crack
  ```

After each audit, a YAML report (e.g., `report.yaml`) is generated and can be reused.

## Contributors

This project was developed by students of the **M2SSI program (2024–2025)** as part of a cybersecurity academic project.  
Feel free to contribute via issues or pull requests!


## Project Status

**In development** – HMS is still under active development. Core features are functional, but improvements, optimizations, and additional modules are planned.  
Use with caution in production environments, and always review recommendations before applying them.


## Useful Resources

- [ANSSI GNU/Linux Security Recommendations](https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux)
- [ANSSI OpenSSH Secure Usage Guide](https://cyber.gouv.fr/publications/usage-securise-dopenssh)
- [John the Ripper](https://www.openwall.com/john/)
- [Project GitHub Repo](https://github.com/HMS-2025/HMS)


## 📄 License
- GNU General Public Licence


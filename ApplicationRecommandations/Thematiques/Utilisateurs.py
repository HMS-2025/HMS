import os
from ApplicationRecommandations.execute_command import execute_ssh_command

# ============================
# Fonction utilitaire commune
# ============================

def save_yaml_fix_report_utilisateurs(data, output_file, rules, niveau):
    if not data:
        return

    output_dir = "GenerationRapport/RapportCorrections"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)

    with open(output_path,eau in niveaux and rule_id in niveaux[niveau]:
                    comment = niveaux[niveau][rule_id][1]
                    file.write(f"  {rule_id}:  # {comment} ({thematique})\n")
                    file.write(f"    status: {status}\n")

    print(f"✅ Rapport des corrections UTILISATEURS généré : {output_path}")

# ============================
# RÈGLES UTILISATEURS "w", encoding="utf-8") as file:
        file.write("corrections:\n")

        for rule_id, status in data.items():
            for thematique, niveaux in rules.items():
                if niv
# ============================

def apply_r32(serveur, report):
    """
    Applique la règle R32 : Expirer les sessions utilisateur locales inactives.
    """
    r32_data = report.get("utilisateurs", {}).get("R32", {})

    if not r32_data.get("appliquer", False):
        print("✅ R32 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R32 : Expiration des sessions locales...")

    fix_success = True

    attendus = r32_data.get("éléments_attendus", {})
    tmout_value = attendus.get("TMOUT")
    logind_conf = attendus.get("logind_conf", {})

    if not tmout_value or not logind_conf:
        print("❌ R32 : Données attendues manquantes dans le rapport !")
        return "Erreur : Données manquantes"

    # Sauvegardes HMS
    execute_ssh_command(serveur, "sudo cp -n /etc/profile /etc/profile.HMS.bak")
    execute_ssh_command(serveur, "sudo cp -n /etc/bash.bashrc /etc/bash.bashrc.HMS.bak")
    execute_ssh_command(serveur, "sudo cp -n /etc/systemd/logind.conf /etc/systemd/logind.conf.HMS.bak")
    execute_ssh_command(serveur, "sudo cp -n /etc/login.defs /etc/login.defs.HMS.bak")

    # CONFIGURATION DE TMOUT
    tmout_directives = [
        f"TMOUT={tmout_value}",
        "readonly TMOUT",
        "export TMOUT"
    ]

    tmout_files = ["/etc/profile", "/etc/bash.bashrc"]

    for file in tmout_files:
        print(f"➡️  Mise à jour de {file}")
        for directive in tmout_directives:
            param_name = directive.split('=')[0]
            execute_ssh_command(serveur, f"sudo sed -i '/^{param_name}/d' {file}")
            execute_ssh_command(serveur, f"echo '{directive}' | sudo tee -a {file}")

    # CONFIGURATION DU LOGIN_TIMEOUT DANS login.defs
    print("➡️  Mise à jour de /etc/login.defs")
    execute_ssh_command(serveur, "sudo sed -i '/^LOGIN_TIMEOUT/d' /etc/login.defs")
    execute_ssh_command(serveur, "echo 'LOGIN_TIMEOUT 60' | sudo tee -a /etc/login.defs")

    # CONFIGURATION DU logind.conf
    print("➡️  Mise à jour de /etc/systemd/logind.conf")
    for param, value in logind_conf.items():
        execute_ssh_command(serveur, f"sudo sed -i '/^{param}/d' /etc/systemd/logind.conf")
        execute_ssh_command(serveur, f"echo '{param}={value}' | sudo tee -a /etc/systemd/logind.conf")

    print("🔄 Redémarrage de systemd-logind...")
    execute_ssh_command(serveur, "sudo systemctl restart systemd-logind")

    print("✅ R32 : Expiration des sessions utilisateur locales configurée.")
    return "Appliqué" if fix_success else "Erreur"

def apply_r69(serveur, report):
    """
    Applique la règle R69 : Sécuriser les accès aux bases utilisateurs distantes.
    """
    r69_data = report.get("utilisateurs", {}).get("R69", {})

    if not r69_data.get("appliquer", False):
        print("✅ R69 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R69 : Sécurisation des accès aux bases utilisateurs distantes...")

    uses_remote_db = r69_data.get("éléments_detectés", {}).get("uses_remote_db")
    secure_connection = r69_data.get("éléments_detectés", {}).get("secure_connection")
    binddn_user = r69_data.get("éléments_detectés", {}).get("binddn_user")
    limited_rights = r69_data.get("éléments_detectés", {}).get("limited_rights")

    if uses_remote_db in [None, "None"]:
        print("➡️ Aucun annuaire distant détecté, aucune action requise.")
        return "Conforme"

    if secure_connection.lower() not in ["start_tls", "ssl", "tls"]:
        print("🔧 Configuration TLS manquante : ajout de la sécurité TLS...")
        execute_ssh_command(serveur, "sudo sed -i '/^TLS_CACERT/d' /etc/ldap/ldap.conf")
        execute_ssh_command(serveur, "echo 'TLS_CACERT /etc/ssl/certs/ca-certificates.crt' | sudo tee -a /etc/ldap/ldap.conf")

    if binddn_user == "Not properly defined":
        print("🔧 BindDN incorrect : définition d'un utilisateur de liaison restreint...")
        execute_ssh_command(serveur, "sudo sed -i '/^binddn/d' /etc/ldap/ldap.conf")
        execute_ssh_command(serveur, "echo 'binddn cn=service_account,dc=example,dc=com' | sudo tee -a /etc/ldap/ldap.conf")

    if limited_rights != "Yes":
        print("🔧 Limitation des droits : vérification manuelle des ACL dans LDAP recommandée.")

    execute_ssh_command(serveur, "sudo systemctl restart nslcd || true")
    execute_ssh_command(serveur, "sudo systemctl restart sssd || true")

    print("✅ R69 : Accès aux bases utilisateurs distantes sécurisés.")
    return "Appliqué"

def apply_r70(serveur, report):
    """
    Applique la règle R70 : Séparer les comptes système et administrateurs de l'annuaire.
    """
    r70_data = report.get("utilisateurs", {}).get("R70", {})

    if not r70_data.get("appliquer", False):
        print("✅ R70 : Aucune action nécessaire.")
        return "Conforme"

    print("🔧 Application de la règle R70 : Séparation des comptes système et administrateurs...")

    attendus = r70_data.get("éléments_attendus", {})
    admin_users_attendus = attendus.get("admin_users", [])
    ldap_users_attendus = attendus.get("ldap_users", [])

    execute_ssh_command(serveur, "sudo cp -n /etc/security/access.conf /etc/security/access.conf.HMS.bak")
    execute_ssh_command(serveur, "sudo cp -n /etc/pam.d/common-auth /etc/pam.d/common-auth.HMS.bak")
    execute_ssh_command(serveur, "sudo cp -n /etc/pam.d/sshd /etc/pam.d/sshd.HMS.bak")

    execute_ssh_command(serveur, "sudo sed -i '/HMS_R70/d' /etc/security/access.conf")

    access_rules = []

    access_rules.append("# HMS_R70: Règles de séparation des comptes système/admin")
    access_rules.append("+:root:LOCAL")

    if admin_users_attendus:
        for admin_user in admin_users_attendus:
            access_rules.append(f"+:{admin_user}:LOCAL")
    else:
        access_rules.append("# Aucun utilisateur admin spécifié dans les éléments attendus.")

    if ldap_users_attendus:
        for ldap_user in ldap_users_attendus:
            access_rules.append(f"-:{ldap_user}:ALL")
    else:
        access_rules.append("# Aucun utilisateur LDAP spécifié, aucune restriction particulière.")

    access_rules.append("-:ALL:ALL")

    for rule in access_rules:
        execute_ssh_command(serveur, f"echo '{rule}' | sudo tee -a /etc/security/access.conf")

    modules_to_check = [
        "/etc/pam.d/common-auth",
        "/etc/pam.d/sshd"
    ]

    for pam_file in modules_to_check:
        check_cmd = f"sudo grep -q 'pam_access.so' {pam_file} || echo 'account required pam_access.so' | sudo tee -a {pam_file}"
        execute_ssh_command(serveur, check_cmd)

    print("✅ R70 : Séparation des comptes système/admin appliquée avec succès.")
    return "Appliqué"

# ============================
# FONCTION PRINCIPALE UTILISATEURS
# ============================

def apply_utilisateurs(serveur, niveau, report_data):
    if report_data is None:
        report_data = {}

    fix_results = {}

    rules = {
        "utilisateurs": {
            "moyen": {
                "R32": (apply_r32, "Expirer les sessions utilisateur locales"),
                "R69": (apply_r69, "Sécuriser les accès aux bases utilisateurs distantes"),
                "R70": (apply_r70, "Séparer les comptes système et administrateurs de l'annuaire")
            },
            "renforce": {
                
            }
        }
    }

    if niveau in rules["utilisateurs"]:
        for rule_id, (function, comment) in rules["utilisateurs"][niveau].items():
            print(f"-> Application de la règle {rule_id} : {comment}")
            fix_results[rule_id] = function(serveur, report_data)

    output_file = f"fixes_{niveau}_utilisateurs.yml"
    save_yaml_fix_report_utilisateurs(fix_results, output_file, rules, niveau)

    print(f"\n✅ Correctifs appliqués - UTILISATEURS - Niveau {niveau.upper()} : {output_file}")
    return fix_results

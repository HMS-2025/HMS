#############################################################################################
#                                                                                           #
#                    Appling Middle Recommandation for system                                 #    
#                                                                                           #
#############################################################################################
import yaml
# Charger les références depuis Reference_min.yaml ou Reference_Moyen.yaml
def load_report_yaml(niveau):
    """Charge le fichier de référence correspondant au niveau choisi (min ou moyen)."""
    file_path = f"./GenerationRapport/RapportAnalyse/analyse_{niveau}.yml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            report = yaml.safe_load(file)
        return report or {}
    except Exception as e:
        print(f"Erreur lors du chargement de {file_path} : {e}")
        return {}
    
def load_reference_data_yaml(niveau):
    """Charge le fichier de référence correspondant au niveau choisi (min ou moyen)."""
    file_path = f"./AnalyseConfiguration/Reference_{niveau}.yaml"
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            report = yaml.safe_load(file)
        return report or {}
    except Exception as e:
        print(f"Erreur lors du chargement de {file_path} : {e}")
        return {}

def update_report(data):
    report_path = f"./GenerationRapport/RapportAnalyse/analyse_moyen.yml"
    with open(report_path, 'w', encoding="utf-8") as file:
        yaml.safe_dump(data, file)
        

#######################################Partie systeme ##########################
def apply_R8(serveur, report):
    """Configure memory security options at boot."""

    if report.get("system", {}).get("R8", {}).get("apply", True):
        r8_detected_elements = report.get("system", {}).get("R8", {}).get("detected_elements", [])
        expected_elements = report.get("system", {}).get("R8", {}).get("expected_elements", [])

        print("\n⚠️   Applying rule R8 for memory security options at boot   ⚠️\n")

        # Détection du fichier de configuration GRUB à modifier
        grub_files = ["/etc/default/grub.d/50-cloudimg-settings.cfg", "/etc/default/grub"]
        grub_file = None

        for file in grub_files:
            stdin, stdout, stderr = serveur.exec_command(f"test -f {file} && grep -q 'GRUB_CMDLINE_LINUX' {file} && echo 'FOUND' || echo 'MISSING'")
            if stdout.read().decode().strip() == "FOUND":
                grub_file = file
                break

        if not grub_file:
            print("❌ Grub configuration file is not found.")
            return

        grub_backup = f"{grub_file}.htms"

        try:
            # Sauvegarde du fichier
            print(f"📝 We are saving your grub file {grub_file} as {grub_backup}")            
            serveur.exec_command(f"sudo cp -n {grub_file} {grub_backup}")
           
            # Modification des paramètres GRUB
            for param in expected_elements:
                key, new_value = param.split("=", 1)

                # Vérifier si l'élément est déjà détecté dans le fichier GRUB
                if any(f"{key}=" in line for line in r8_detected_elements):
                    print(f"🔄 Mise à jour de {key} avec {new_value}")
                    # Mise à jour de la ligne existante avec la nouvelle valeur
                    update_command = f"sudo sed -i 's|{key}=[^ ]*|{key}={new_value}|g' {grub_file}"
                    serveur.exec_command(update_command)
                else:
                    # Ajouter la clé si elle n'est pas détectée
                    print(f"➕ Ajout de {key}={new_value}")
                    # Commande pour commenter une ligne existante si elle contient la clé avec une mauvaise valeur
                    comment_command = f"sudo sed -i '/GRUB_CMDLINE_LINUX_DEFAULT=.*{key}=[^ ]*/s/^/#/' {grub_file}"
                    serveur.exec_command(comment_command)

                    # Ajouter la nouvelle clé avec la bonne valeur
                    add_command = f"echo \"GRUB_CMDLINE_LINUX_DEFAULT=\\\"{key}={new_value}\\\"\" | sudo tee -a {grub_file} > /dev/null"
                    serveur.exec_command(add_command)


            # Mise à jour de GRUB
            print("🔄 GRUB updating ...")
            serveur.exec_command("sudo update-grub")
            print("✅ GRUB is successfully updated.")

            # Mise à jour du rapport
            report["system"]["R8"]["apply"] = False
            report["system"]["R8"]["status"] = "Conforme"
            report["system"]["R8"]["detected_elements"] = list(set(r8_detected_elements) | set(expected_elements))
            update_report(report)
            print("✅ The R8 is successfully applied and report updated 📁")

        except Exception as e:
            print(f"❌ Error occured in GRUB updating : {e}")


def apply_R9(serveur, report,reference_data):
    """Configure kernel security settings on the server."""
    
    if report.get("system", {}).get("R9", {}).get("apply", True):
        print("\n⚠️   Applying rule R9 for kernel security settings   ⚠️\n")
        
        # Récupérer les valeurs attendues et détectées
        expected_elements = report.get("system", {}).get("R9", {}).get("expected_elements", [])
        detected_elements = report.get("system", {}).get("R9", {}).get("detected_elements", [])
        
        # Vérification si les éléments attendus et détectés sont présents
        if not expected_elements or not detected_elements:
            print("❌ Error: No expected or detected kernel security settings found.")
            return
        
        # Paramètres de sécurité attendus
        expected_settings = reference_data.get("R9", {}).get("expected", {})
        kernel_settings = list(expected_settings.keys()) 
        # Fichier de configuration sysctl
        sysctl_file = "/etc/sysctl.conf"
        
        # Créer un backup avant toute modification avec `cp -n`
        backup_file = f"{sysctl_file}.htms"
        try:
            print(f"🔒 Creating backup of {sysctl_file} as {backup_file} (if not exists)")
            serveur.exec_command(f"sudo cp -n {sysctl_file} {backup_file}")
        except Exception as e:
            print(f"❌ Error creating backup: {e}")
            return
        
        try:
            updated = False
            for i in range(len(expected_elements)):
                expected_value = expected_elements[i]
                detected_value = detected_elements[i]
                setting = kernel_settings[i]
                
                if expected_value != detected_value:
                    # Si la valeur attendue diffère de la valeur détectée, on applique la valeur attendue
                    print(f"⚙️ {setting}: expected {expected_value} but got {detected_value}")
                    serveur.exec_command(f"echo '{setting} = {expected_value}' | sudo tee -a {sysctl_file} > /dev/null")
                    updated = True

            if updated:
                # Appliquer les changements immédiatement
                print("✅ Applying kernel security settings.")
                serveur.exec_command('sudo sysctl -p')
            else:
                print("✅ All kernel security settings are already applied.")
        
        except Exception as e:
            print(f"❌ Error updating sysctl: {e}")
        
        # Mise à jour du rapport et sauvegarde
        report["system"]["R9"]["apply"] = False
        report["system"]["R9"]["status"] = "Conforme"
        update_report(report)
        print("✅ The rule R9 is successfully applied and report updated 📁")
    else:
        return None



def apply_R11(serveur, report):
    """Enable and configure Yama LSM on the server if not already applied."""
    
    if report.get("system", {}).get("R11", {}).get("apply", True):
        r11_detected_elements = report.get("system", {}).get("R11", {}).get("detected_elements", [])
        
        print("\n⚠️   Applying rule R11 for Yama LSM configuration   ⚠️\n")
        
        # Paramètre attendu à appliquer
        expected_element = 'kernel.yama.ptrace_scope: "1"'
        
        # Fichier de configuration sysctl
        sysctl_file = "/etc/sysctl.conf"
        sysctl_backup = "/etc/sysctl.conf.htms"
        
        try:
            # Créer une sauvegarde si elle n'existe pas
            print("📝 Creating backup of sysctl file if not already present.")
            serveur.exec_command(f"sudo cp -n {sysctl_file} {sysctl_backup}")
            
            if expected_element not in r11_detected_elements:
                # Appliquer l'élément attendu dans le fichier sysctl
                print(f"⚙️ Applying setting {expected_element}")
                serveur.exec_command(f"echo 'kernel.yama.ptrace_scope = 1' | sudo tee -a {sysctl_file} > /dev/null")
                
                # Appliquer les changements immédiatement
                print("✅ Applying Yama LSM settings.")
                serveur.exec_command('sudo sysctl -p')
            else:
                print("✅ Yama LSM setting already applied.")
        
        except PermissionError as e:
            print(f"❌ Permission error: {e}")
        except FileNotFoundError as e:
            print(f"❌ File not found: {e}")
        except Exception as e:
            print(f"❌ Error updating sysctl: {e}")
        
        # Mise à jour du rapport
        report["system"]["R11"]["apply"] = False
        report["system"]["R11"]["status"] = "Conforme"
        update_report(report)
        print("✅ The rule R11 is successfully applied and report updated 📁")
    else:
        return None
   

def apply_R14(serveur, report, reference_data):
    """Configure filesystem security settings on the server if not already applied."""
    
    if report.get("system", {}).get("R14", {}).get("apply", True):
        r14_detected_elements = report.get("system", {}).get("R14", {}).get("detected_elements", [])
        r14_expected_elements = report.get("system", {}).get("R14", {}).get("expected_elements", [])
        
        print("\n⚠️   Applying rule R14 for filesystem security settings   ⚠️\n")
        
        # Paramètres attendus à appliquer
        expected_elements = list(reference_data.get("R14", {}).get("expected", {}).items())
        
        # Comparer les listes des éléments détectés et attendus
        if r14_detected_elements != r14_expected_elements:
            print("🔍 Differences detected between expected and applied settings.")
            
            sysctl_file = "/etc/sysctl.conf"
            sysctl_backup = "/etc/sysctl.conf.htms"
            
            try:
                # Créer une sauvegarde si elle n'existe pas
                print("📝 Creating backup of sysctl file if not already present.")
                serveur.exec_command(f"sudo cp -n {sysctl_file} {sysctl_backup}")
                
                updated = False
                # Vérifier chaque paramètre attendu et l'appliquer si nécessaire
                for i in range(min(len(r14_detected_elements), len(r14_expected_elements), len(expected_elements))):
                    detected_value = r14_detected_elements[i]
                    expected_value = r14_expected_elements[i]
                    setting, value_to_apply = expected_elements[i]
                    
                    if detected_value != expected_value:
                        expected_line = f"{setting} = {value_to_apply}"
                        print(f"⚙️ Applying setting {expected_line}")
                        serveur.exec_command(f"echo '{expected_line}' | sudo tee -a {sysctl_file} > /dev/null")
                        updated = True
                
                if updated:
                    # Appliquer les changements immédiatement
                    print("✅ Applying filesystem security settings.")
                    serveur.exec_command('sudo sysctl -p')
                else:
                    print("✅ All filesystem security settings are already applied.")
            
            except PermissionError as e:
                print(f"❌ Permission error: {e}")
            except FileNotFoundError as e:
                print(f"❌ File not found: {e}")
            except Exception as e:
                print(f"❌ Error updating sysctl: {e}")
            
            # Mise à jour du rapport
            report["system"]["R14"]["apply"] = False
            report["system"]["R14"]["status"] = "Conforme"
            report["system"]["R14"]["detected_elements"] = [value for key, value in expected_elements]
            update_report(report)
            print("✅ The rule R14 is successfully applied and report updated 📁")
        else:
            print("✅ No changes needed, system already compliant.")
    else:
        return 
    
#test
"""
def apply_system(serveur, niveau):
     report = load_report_yaml(niveau)     
     reference_data= load_reference_data_yaml(niveau)
     #apply_R67(serveur, report,reference_data)
     #apply_R8(serveur, report)
     #apply_R9(serveur, report,reference_data)
     #apply_R14(serveur, report,reference_data)
 """



####################### Fin de de definitions des fonction de gestion d'acess niveau moyen ############################


# ============================
# Fonction principale par niveau pour GESTION ACCÈS
# ============================
def apply_system(serveur, niveau, report_data):
    if report_data is None:
        report_data = {}

        fix_results = {}

        rules = {
                "min": {},
                "moyen": {            
                "R8": (apply_R8, "Configure memory security options at boot"),
                "R9": (apply_R9, "Configure kernel security settings"),
                "R11": (apply_R11, "Enable and configure Yama LSM"),
                "R14": (apply_R14, "Configure filesystem security settings"),
                
            },
            "avancé": {
                # À compléter si besoin
            }
        }

        if niveau in rules:
            for rule_id, (function, comment) in rules[niveau].items():
                print(f"-> Appling  rule {rule_id} : {comment}")
                fix_results[rule_id] = function(serveur, report_data)

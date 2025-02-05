import subprocess
import yaml
import os

def analyse_gestion_acces(serveur, niveau="min"):
    """Analyse la gestion des accès en fonction du niveau spécifié et génère un unique rapport YAML."""
    report = {}
    
    if niveau == "min":
        print("-> Vérification de la désactivation des comptes inutilisés (R30)")
        report["inactive_accounts"] = get_inactive_users()
        
        print("-> Vérification des fichiers sans propriétaire (R53)")
        report["orphan_files"] = find_orphan_files("/")
        
        print("-> Vérification des exécutables avec setuid/setgid (R56)")
        report["setuid_sgid_files"] = find_files_with_setuid_setgid()
    
    save_yaml_report(report, "gestion_acces_minimal.yml")
    print(f"Analyse terminée. Rapport généré : gestion_acces_minimal.yml")

# R30 - Désactiver les comptes utilisateur inutilisés
def get_standard_users():
    command = "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print $1}' /etc/passwd"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return set(result.stdout.strip().split("\n"))

def get_active_users():
    who_command = "who | awk '{print $1}'"
    w_command = "w -h | awk '{print $1}'"
    who_result = subprocess.run(who_command, shell=True, capture_output=True, text=True)
    w_result = subprocess.run(w_command, shell=True, capture_output=True, text=True)
    who_users = set(who_result.stdout.strip().split("\n"))
    w_users = set(w_result.stdout.strip().split("\n"))
    return who_users.union(w_users)

def get_recent_users():
    command = "last -n 50 | awk '{print $1}' | sort | uniq"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return set(result.stdout.strip().split("\n"))

def get_inactive_users():
    standard_users = get_standard_users()
    active_users = get_active_users()
    recent_users = get_recent_users()
    inactive_users = standard_users - active_users - recent_users
    return list(inactive_users)

# R53 - Éviter les fichiers ou répertoires sans utilisateur ou sans groupe connu
def find_orphan_files(directory="/"):
    command = f"find {directory} -xdev \\( -nouser -o -nogroup \\) -print"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    orphan_files = result.stdout.strip().split("\n")
    return [file for file in orphan_files if file]

# R56 - Éviter l’usage d’exécutables avec les droits spéciaux setuid et setgid
def find_files_with_setuid_setgid():
    command = "find /tmp -type f \\( -perm -4000 -o -perm -2000 \\) -print 2>/dev/null"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    files_with_suid_sgid = result.stdout.strip().split("\n")
    return [file for file in files_with_suid_sgid if file]

# R54 - Activer le sticky bit sur les répertoires inscriptibles (pas encore codé)

def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    # Définir le chemin du dossier de sortie
    output_dir = "GenerationRapport/RapportAnalyse"
    
    # S'assurer que le dossier existe
    os.makedirs(output_dir, exist_ok=True)
    
    # Construire le chemin complet du fichier de sortie
    output_path = os.path.join(output_dir, output_file)
    
    # Écriture des données dans le fichier YAML
    with open(output_path, "w") as file:
        yaml.dump(data, file, default_flow_style=False)
    
    print(f"Rapport généré : {output_path}")
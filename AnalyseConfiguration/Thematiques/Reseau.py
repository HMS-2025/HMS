import paramiko
import yaml
import os
import subprocess

# Charger les références depuis Reference_Min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_Min.yaml"):
    """Charge le fichier Reference_Min.yaml et retourne son contenu."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data
    except Exception as e:
        print(f"Erreur lors du chargement de Reference_Min.yaml : {e}")
        return {}

# Vérification de conformité des interfaces réseau
def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie si les interfaces réseau sont conformes selon Reference_Min.yaml."""
    expected_value = reference_data.get(rule_id, {}).get("expected", {})

    allowed_interfaces = set(expected_value.get("restricted_interfaces", []))
    detected_interfaces = set(rule_value["interfaces_detectees"])

    # Interfaces locales à exclure totalement des interfaces autorisées
    local_interfaces = {
        "127.0.0.1", "::1", "fe80::/10",
        "127.0.0.53%lo", "127.0.0.54", "localhost"
    }

    # Interfaces non conformes = Tout ce qui est détecté mais non autorisé
    non_compliant_interfaces = detected_interfaces - allowed_interfaces
    non_compliant_interfaces.update(local_interfaces & detected_interfaces)

    return {
        "status": "Non conforme" if non_compliant_interfaces else "Conforme",
        "interfaces_autorisees": list(allowed_interfaces - local_interfaces),  # Exclut les locales
        "interfaces_detectees": list(detected_interfaces),
        "interfaces_non_conformes": list(non_compliant_interfaces) if non_compliant_interfaces else "Aucune",
        "appliquer": False if non_compliant_interfaces else True
    }

# Fonction principale pour analyser la configuration réseau
def analyse_reseau(serveur, niveau="min", reference_data=None):
    """Analyse les interfaces réseau et génère un rapport YAML avec conformité."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Vérification des interfaces réseau actives (R80)")
        detected_interfaces = get_network_interfaces()
        report["R80"] = check_compliance("R80", {"interfaces_detectees": detected_interfaces}, reference_data)

    # Enregistrement du rapport
    save_yaml_report(report, "reseau_minimal.yml")

    # Calcul du taux de conformité
    total_rules = len(report)
    conforming_rules = sum(1 for result in report.values() if result["status"] == "Conforme")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    print(f"\nTaux de conformité du niveau minimal (Réseau) : {compliance_percentage:.2f}%")

# R80 - Récupérer la liste des interfaces réseau à partir de `ss -tulnp`
def get_network_interfaces():
    """Récupère la liste des interfaces réseau en écoute sur le système et filtre les résultats."""
    try:
        # Exécuter la commande et récupérer les interfaces réseau en écoute
        command = "ss -tulnp | awk '{print $5}' | cut -d':' -f1 | sort -u"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        interfaces = result.stdout.strip().split("\n")

        # Nettoyage des résultats : suppression des vides, interfaces locales et doublons
        cleaned_interfaces = set()
        for iface in interfaces:
            iface = iface.strip()
            if iface and iface not in ["0.0.0.0", "::", "localhost"] and not iface.startswith("fe80::"):
                cleaned_interfaces.add(iface.replace("[", "").replace("]", ""))

        return list(cleaned_interfaces)
    except Exception as e:
        print(f"Erreur lors de la récupération des interfaces réseau : {e}")
        return []

# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
    print(f"Rapport généré : {output_path}")

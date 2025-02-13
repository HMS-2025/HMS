import paramiko
import yaml
import os

# Charger les références depuis Reference_min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    """Charge le fichier Reference_min.yaml et retourne son contenu."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data
    except Exception as e:
        print(f"Erreur lors du chargement de Reference_min.yaml : {e}")
        return {}

# Vérification de conformité des interfaces réseau
def check_compliance(rule_id, rule_value, reference_data):
    """Vérifie si les interfaces réseau sont conformes selon Reference_min.yaml."""
    expected_value = reference_data.get(rule_id, {}).get("expected", {})

    allowed_interfaces = set(expected_value.get("restricted_interfaces", []))
    local_interfaces = set(expected_value.get("local_interfaces", []))  # Interfaces locales définies dans le YAML
    detected_interfaces = set(rule_value["interfaces_detectees"])
    active_interfaces = set(rule_value["interfaces_utilisees"])

    # Interfaces non conformes = Écoute mais non utilisées
    unused_interfaces = detected_interfaces - active_interfaces
    unused_interfaces -= local_interfaces  # Exclure les interfaces locales

    return {
        "status": "Non conforme" if unused_interfaces else "Conforme",
        "interfaces_detectees": list(detected_interfaces),
        "interfaces_utilisees": list(active_interfaces),
        "interfaces_non_utilisees": list(unused_interfaces) if unused_interfaces else "Aucune",
        "appliquer": False if unused_interfaces else True
    }

# Fonction principale pour analyser la configuration réseau
def analyse_reseau(serveur, niveau="min", reference_data=None):
    """Analyse les interfaces réseau et génère un rapport YAML avec conformité."""
    report = {}

    if reference_data is None:
        reference_data = load_reference_yaml()

    if niveau == "min":
        print("-> Vérification des interfaces réseau actives et utilisées (R80)")
        detected_interfaces = get_network_interfaces_with_traffic(serveur)

        active_interfaces_tcp = [iface for iface, data in detected_interfaces.items() if data["protocol"] == "TCP" and data["status"] == "Trafic actif"]
        active_interfaces_udp = [iface for iface, data in detected_interfaces.items() if data["protocol"] == "UDP" and data["status"] == "Trafic actif"]

        report["R80"] = {
            "status": "Non conforme" if active_interfaces_tcp or active_interfaces_udp else "Conforme",
            "interfaces_detectees": list(detected_interfaces.keys()),
            "interfaces_utilisees_tcp": active_interfaces_tcp,
            "interfaces_utilisees_udp": active_interfaces_udp,
            "interfaces_non_utilisees_tcp": [iface for iface, data in detected_interfaces.items() if data["protocol"] == "TCP" and data["status"] == "Aucun trafic"],
            "interfaces_non_utilisees_udp": [iface for iface, data in detected_interfaces.items() if data["protocol"] == "UDP" and data["status"] == "Aucun trafic"],
            "appliquer": False if active_interfaces_tcp or active_interfaces_udp else True
        }

    # Enregistrement du rapport
    save_yaml_report(report, "reseau_minimal.yml")

    # Calcul du taux de conformité
    total_rules = len(report)
    conforming_rules = sum(1 for result in report.values() if result["status"] == "Conforme")
    compliance_percentage = (conforming_rules / total_rules) * 100 if total_rules > 0 else 0

    print(f"\nTaux de conformité du niveau minimal (Réseau) : {compliance_percentage:.2f}%")

# R80 - Récupérer la liste des interfaces réseau et leur statut de trafic, différencié TCP et UDP
def get_network_interfaces_with_traffic(serveur):
    """Récupère les interfaces réseau avec leur protocole et leur statut de trafic."""
    try:
        command = "ss -tulnp | awk 'NR>1 {print $1, $3, $4, $5}' | sed 's/\[//g; s/\]//g'"
        stdin, stdout, stderr = serveur.exec_command(command)
        lines = stdout.read().decode().strip().split("\n")

        interfaces = {}
        for line in lines:
            parts = line.split()
            if len(parts) == 4:
                protocol, recv_q, send_q, local_address = parts
                recv_q, send_q = int(recv_q), int(send_q)

                # Détermine si l'interface a du trafic actif
                status = "Aucun trafic" if recv_q == 0 and send_q == 0 else "Trafic actif"
                interfaces[local_address] = {
                    "protocol": "TCP" if protocol == "tcp" else "UDP",
                    "recv_q": recv_q,
                    "send_q": send_q,
                    "status": status
                }

        return interfaces

    except Exception as e:
        print(f"Erreur lors de la récupération des interfaces réseau avec trafic : {e}")
        return {}

# Fonction d'enregistrement des rapports
def save_yaml_report(data, output_file):
    """Enregistre les données d'analyse dans un fichier YAML dans le dossier dédié."""
    output_dir = "GenerationRapport/RapportAnalyse"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w", encoding="utf-8") as file:
        yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
    print(f"Rapport généré : {output_path}")

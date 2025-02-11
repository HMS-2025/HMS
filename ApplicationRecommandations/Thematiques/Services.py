import yaml
import subprocess

def ask_for_approval(service):
    """Demande l'approbation de l'utilisateur pour appliquer la règle à un service."""
    response = input(f"Souhaitez-vous désactiver le service {service} (o/n) ? ").strip().lower()
    return response == 'o'

def apply_recommandation_service_min(yaml_file, client):
    """Applique les recommandations de la règle R62 pour désactiver les services non nécessaires et met à jour le fichier YAML."""
    
    # Charger le fichier YAML
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    # Récupérer la règle R62
    rule_data = data.get('R62', {})
    
    # Vérifier si la règle doit être appliquée (appliquer == False)
    if rule_data.get('appliquer', False):
        print("La règle R62 est déjà appliquée.")
        return

    # Services attendus à retirer et services interdits détectés
    services_attendus_a_retirer = rule_data.get('services_attendus_a_retirer', [])
    services_interdits_detectes = rule_data.get('services_interdits_detectes', [])

    # Services inattendus détectés (qui ne sont ni attendus à retirer ni interdits)
    print("Services inattendus détectés (à vérifier) :")
    unexpected_services = list(set(services_interdits_detectes) - set(services_attendus_a_retirer))
    print(f"{unexpected_services}")

    # Demander l'approbation pour appliquer la règle
    if not ask_for_approval("R62"):
        print("La règle R62 ne sera pas appliquée.")
        return

    # Appliquer les recommandations pour les services inattendus
    try:
        print("Désactivation des services inattendus...")

        # Pour chaque service inattendu, demander l'approbation avant de le désactiver
        for service in unexpected_services:
            service_status = subprocess.run(['systemctl', 'is-active', '--quiet', service], check=False)
            if service_status.returncode == 0:
                confirmation = ask_for_approval(service)
                if confirmation:
                    # Désactiver et arrêter le service
                    subprocess.run(['sudo', 'systemctl', 'stop', service], check=True)
                    subprocess.run(['sudo', 'systemctl', 'disable', service], check=True)
                    print(f"Le service {service} a été désactivé et arrêté.")
                else:
                    print(f"Le service {service} n'a pas été désactivé.")
            else:
                print(f"Le service {service} n'est pas actif, aucune action nécessaire.")

        # Mise à jour du YAML avec les nouvelles données
        rule_data['status'] = 'Conforme'
        rule_data['appliquer'] = True
        rule_data['services_interdits_detectes'] = []  # Réinitialiser les services interdits détectés
        data['R62'] = rule_data

        # Sauvegarder les modifications dans le fichier YAML
        with open(yaml_file, 'w', encoding="utf-8") as file:
            yaml.safe_dump(data, file)

        print(f"Le fichier YAML a été mis à jour avec succès.")

        # Retourner une réponse au client
        client.send("R62 - Recommandations appliquées et fichier YAML mis à jour.")

    except Exception as e:
        print(f"Erreur lors de l'application des règles R62 : {e}")
        client.send(f"Erreur lors de l'application de la règle R62 : {e}")


#apply_recommandation_service_min(yaml_file_service_min, client)

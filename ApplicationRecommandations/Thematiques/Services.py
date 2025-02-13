import yaml
import subprocess

def ask_for_approval(service, rule):
    """Demande l'approbation de l'utilisateur pour appliquer la regle à un service.
       L'utilisateur peut aussi entrer 'q' pour quitter l'application de la règle."""
    while True:
        response = input(f"Souhaitez-vous desactiver le service {service} en application de la regle {rule} ? (o/n/q pour quitter) ").strip().lower()
        if response in ['o', 'n', 'q']:
            return response
        print("Réponse invalide. Entrez 'o' pour oui, 'n' pour non, ou 'q' pour quitter.")

def apply_recommandation_service_min(yaml_file, client):
    """Applique les recommandations de la regle R62 pour désactiver les services non nécessaires 
       et met à jour le fichier YAML uniquement si l'application de la règle est un succès."""
    
    # Charger le fichier YAML
    with open(yaml_file, 'r', encoding="utf-8") as file:
        data = yaml.safe_load(file)

    # Récupérer la règle R62
    rule_data = data.get('R62', {})

    # Vérifier si la règle est déjà appliquée
    if rule_data.get('appliquer', False):
        print("La regle R62 est déjà appliquee.")
        return

    # Services interdits détectés et attendus à retirer
    services_interdits_detectes = rule_data.get('services_interdits_detectes', [])
    services_attendus_a_retirer = rule_data.get('services_attendus_a_retirer', [])

    all_services = list(set(services_interdits_detectes + services_attendus_a_retirer))

    print("\nServices attendus à retirer systematiquement :")
    for service in services_attendus_a_retirer:
        print(f" - {service}")

    print("\nServices détectés à éventuellement retirer :")
    for service in services_interdits_detectes:
        print(f" - {service}")

    # Variable pour suivre le succès global de l'opération
    success = True

    try:
        for service in all_services:
            response = ask_for_approval(service, "R62")
            if response == 'q':
                print("Application de la regle R62 annulee par l'utilisateur.")
                return  # Quitte immédiatement l'application de la règle

            if response == 'o':
                # Vérifier si le service est actif avant de le stopper
                service_status = subprocess.run(['systemctl', 'is-active', '--quiet', service], check=False)
                if service_status.returncode == 0:  # Le service est actif
                    try:
                        subprocess.run(['sudo', 'systemctl', 'stop', service], check=True)
                        subprocess.run(['sudo', 'systemctl', 'disable', service], check=True)
                        print(f"Service {service} desactive et arrete.")
                    except subprocess.CalledProcessError as e:
                        print(f"Erreur lors de l'arret du service {service} : {e}")
                        success = False
                else:
                    print(f"Service {service} deja inactif, aucune action necessaire.")
            else:
                print(f"Le service {service} ne sera pas desactive.")

        if success:
            # Mettre à jour le fichier YAML uniquement en cas de succès complet
            rule_data['status'] = 'Conforme'
            rule_data['appliquer'] = True
            rule_data['services_interdits_detectes'] = []
            data['R62'] = rule_data

            with open(yaml_file, 'w', encoding="utf-8") as file:
                yaml.safe_dump(data, file)

            print("\nLe fichier YAML a ete mis a jour avec succes.")

            # Envoyer une réponse au client selon son type
            if hasattr(client, "exec_command"):  # Si c'est un client SSH (paramiko)
                client.exec_command('echo "R62 - Recommandations appliquees et fichier YAML mis a jour."')
            elif hasattr(client, "sendall"):  # Si c'est un socket
                client.sendall(b"R62 - Recommandations appliquees et fichier YAML mis a jour.\n")
            else:
                print("Client inconnu, impossible d'envoyer un message.")
        else:
            print("\nEchec de l'application complète de la regle R62. Le fichier YAML n'a pas ete mis a jour.")
            if hasattr(client, "exec_command"):
                client.exec_command('echo "Erreur R62 : echec lors de l\'application de la regle, fichier YAML non mis a jour."')
            elif hasattr(client, "sendall"):
                client.sendall(b"Erreur R62 : echec lors de l'application de la regle, fichier YAML non mis a jour.\n")
            else:
                print("Client inconnu, impossible d'envoyer un message.")

    except Exception as e:
        print(f"\nErreur lors de l'application de la regle R62 : {e}")
        if hasattr(client, "exec_command"):
            client.exec_command(f'echo "Erreur R62 : {e}"')
        elif hasattr(client, "sendall"):
            client.sendall(f"Erreur R62 : {e}\n".encode())

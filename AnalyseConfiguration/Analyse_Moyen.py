import yaml
from AnalyseConfiguration.Thematiques.GestionAcces import analyse_gestion_acces
from AnalyseConfiguration.Thematiques.Services import analyse_services
from AnalyseConfiguration.Thematiques.MiseAJour import analyse_mise_a_jour
from AnalyseConfiguration.Thematiques.PolitiqueMotDePasse import analyse_politique_mdp
from AnalyseConfiguration.Thematiques.Reseau import analyse_reseau
from AnalyseConfiguration.Thematiques.Maintenance import analyse_maintenance
from AnalyseConfiguration.Thematiques.JournalisationAudit import analyse_journalisation
from AnalyseConfiguration.Thematiques.Utilisateurs import analyse_utilisateurs
from AnalyseConfiguration.Thematiques.Systeme import analyse_systeme

# Load references from Reference_moyen.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_moyen.yaml"):
    """Loads the Reference_moyen.yaml file and returns its content."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reference_data = yaml.safe_load(file)
        return reference_data
    except Exception as e:
        print(f"Error loading Reference_moyen.yaml: {e}")
        return {}

# Medium-level analysis with compliance
def analyse_moyen(serveur):
    """Executes all medium-level analyses using Reference_moyen.yaml."""
    
    # Load reference data for compliance
    reference_data = load_reference_yaml()
    
    print("\n[Analysis] Access management (medium level)...")
    analyse_gestion_acces(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analysis] Users (medium level)...")
    analyse_utilisateurs(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analysis] System (medium level)...")
    analyse_systeme(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analysis] Services (medium level)...")
    analyse_services(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analysis] Updates (medium level)...")
    analyse_mise_a_jour(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analysis] Password policy (medium level)...")
    analyse_politique_mdp(serveur, niveau="moyen", reference_data=reference_data)

    print("\n[Analysis] Network (medium level)...")
    analyse_reseau(serveur, niveau="moyen", reference_data=reference_data)
    
    print("\n[Analysis] Maintenance (medium level)...")
    analyse_maintenance(serveur, niveau="moyen", reference_data=reference_data)
    
    print("\n[Analysis] Logging and Audit (medium level)...")
    analyse_journalisation(serveur, niveau="moyen", reference_data=reference_data)

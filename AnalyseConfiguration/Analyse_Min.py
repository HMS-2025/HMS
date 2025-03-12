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

# Load references from Reference_min.yaml
def load_reference_yaml(file_path="AnalyseConfiguration/Reference_min.yaml"):
    """Loads the Reference_min.yaml file and returns its content."""
    try:
        with open(file_path, "r") as file:
            reference_data = yaml.safe_load(file)
        return reference_data
    except Exception as e:
        print(f"Error loading Reference_min.yaml: {e}")
        return {}

# Minimal level analysis with compliance
def analyse_min(serveur):
    """Executes all minimal level analyses using Reference_min.yaml."""
    
    # Load reference data for compliance
    reference_data = load_reference_yaml()
    
    print("\n[Analysis] Access management...")
    analyse_gestion_acces(serveur, niveau="min", reference_data=reference_data)

    print("\n[Analysis] Services...")
    analyse_services(serveur, niveau="min", reference_data=reference_data)

    print("\n[Analysis] Updates...")
    analyse_mise_a_jour(serveur, niveau="min", reference_data=reference_data)

    print("\n[Analysis] Password policy...")
    analyse_politique_mdp(serveur, niveau="min", reference_data=reference_data)

    print("\n[Analysis] Network...")
    analyse_reseau(serveur, niveau="min", reference_data=reference_data)
    
    print("\n[Analysis] Maintenance...")
    analyse_maintenance(serveur, niveau="min", reference_data=reference_data)
    
    print("\n[Analysis] Logging and Audit...")
    analyse_journalisation(serveur, niveau="min", reference_data=reference_data)
    
    print("\n[Analysis] Users...")
    analyse_utilisateurs(serveur, niveau="min", reference_data=reference_data)

    print("\n[Analysis] System...")
    analyse_systeme(serveur, niveau="min", reference_data=reference_data)

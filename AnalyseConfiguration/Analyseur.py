from AnalyseConfiguration.AnalyseSSH import check_ssh_configuration_compliance
from AnalyseConfiguration.Analyse_Min import analyse_min as analyse_min_level
from AnalyseConfiguration.Analyse_Moyen import analyse_moyen as analyse_moyen_level

# Analyse SSH et analyse minimale
def analyse_SSH(serveur):
    """Analyse la configuration SSH."""
    check_ssh_configuration_compliance(serveur)

def analyse_min(serveur):
    """Lance l'analyse du niveau minimal."""
    print("\n--- Début de l'analyse niveau MINIMAL ---\n")
    analyse_min_level(serveur) 
    print("\n--- Fin de l'analyse niveau MINIMAL ---\n")

def analyse_moyen(serveur):
    """Lance l'analyse du niveau moyen."""
    print("\n--- Début de l'analyse niveau MOYEN ---\n")
    analyse_moyen_level(serveur)
    print("\n--- Fin de l'analyse niveau MOYEN ---\n")

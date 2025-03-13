from AnalyseConfiguration.AnalyseSSH import check_ssh_configuration_compliance
from AnalyseConfiguration.Analyse_Min import analyse_min as analyse_min_level
from AnalyseConfiguration.Analyse_Moyen import analyse_moyen as analyse_moyen_level
from AnalyseConfiguration.Analyse_Renforce import analyse_renforce as analyse_renforce_level

# SSH analysis
def analyse_SSH(server):
    """Analyzes SSH configuration."""
    check_ssh_configuration_compliance(server)

# Minimal level analysis
def analyse_min(server):
    """Runs the minimal level analysis."""
    print("\n--- Starting MINIMAL level analysis ---\n")
    analyse_min_level(server) 
    print("\n--- Completed MINIMAL level analysis ---\n")

# Intermediate level analysis
def analyse_moyen(server):
    """Runs the intermediate level analysis."""
    print("\n--- Starting INTERMEDIATE level analysis ---\n")
    analyse_moyen_level(server)
    print("\n--- Completed INTERMEDIATE level analysis ---\n")

# Reinforced level analysis
def analyse_renforce(server):
    """Runs the reinforced level analysis."""
    print("\n--- Starting REINFORCED level analysis ---\n")
    analyse_renforce_level(server)
    print("\n--- Completed REINFORCED level analysis ---\n")

import yaml
import tkinter as tk
from tkinter import ttk

class Gui:
    def __init__(self, yaml_file, save_file):
        self.yaml_file = yaml_file
        self.save_file = save_file
        self.data = self.load_yaml()
        self.modified_data = {}
        self.root = tk.Tk()
        self.root.title("Gestion des Règles")
        self.root.geometry("1000x600")
        self.create_widgets()
        self.root.mainloop()

    def load_yaml(self):
        with open(self.yaml_file, "r") as file:
            return yaml.safe_load(file)

    def toggle_apply(self, rule, var, frame):
        self.data[rule["path"]][rule["key"]]["apply"] = var.get()
        self.modified_data.setdefault(rule["path"], {})[rule["key"]] = self.data[rule["path"]][rule["key"]]
        frame.config(bg="green" if var.get() else "red")

    def create_rule_ui(self, parent, section, rule_key, rule, row):
        rule_frame = tk.Frame(parent, bd=2, relief=tk.RIDGE, pady=5, padx=10)
        rule_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=5)

        apply_frame = tk.Frame(parent)
        apply_frame.grid(row=row, column=1, sticky="e", padx=10, pady=5)

        label = tk.Label(rule_frame, text=f"{section} - {rule_key}: {rule.get('status', '')}")
        label.pack(anchor="w")
        label.bind("<Button-1>", lambda e: self.display_description(section, rule_key, rule))

        var = tk.BooleanVar(value=rule.get("apply", False))
        checkbox = ttk.Checkbutton(apply_frame, text="Appliquer", variable=var,
                                   command=lambda: self.toggle_apply({"path": section, "key": rule_key}, var, apply_frame))
        checkbox.pack(anchor="e")
        checkbox.config(state="disabled" if var.get() else "normal")
        rule_frame.config(bg="green" if var.get() else "red")

    def create_widgets(self):
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Ajouter deux colonnes
        left_frame = tk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        right_frame = tk.Frame(main_frame, bg="lightgray")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.description_label = tk.Label(right_frame, text="", wraplength=400, bg="lightgray")
        self.description_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Ajouter un Canvas et une Scrollbar pour le frame de gauche
        canvas = tk.Canvas(left_frame)
        scrollbar = ttk.Scrollbar(left_frame, orient="vertical", command=canvas.yview)
        self.rule_frame = tk.Frame(canvas)

        self.rule_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.rule_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Configurer grid pour s'étendre horizontalement
        self.rule_frame.columnconfigure(0, weight=1)
        self.rule_frame.columnconfigure(1, weight=1)

        row = 0
        for section, rules in self.data.items():
            for rule_key, rule in rules.items():
                if isinstance(rule, dict) and "apply" in rule:
                    self.create_rule_ui(self.rule_frame, section, rule_key, rule, row)
                    row += 1

        save_button = ttk.Button(self.root, text="Sauvegarder", command=self.save_changes)
        save_button.pack(pady=20)

    def display_description(self, section, rule_key, rule):
        description = f"{section} - {rule_key}: {rule.get('status', '')}\n"
        description += rule.get('description', 'No description available.')
        self.description_label.config(text=description)

    def save_changes(self):
        with open(self.save_file, "w") as file:
            yaml.dump(self.modified_data, file, default_flow_style=False, allow_unicode=True)
        print("Modifications sauvegardées")

# Exemple d'utilisation :
# Gui("fichier.yaml", "sauvegarde.yaml")

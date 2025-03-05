import yaml
import tkinter as tk
from tkinter import ttk

class Gui:
    def __init__(self, yaml_file , save_file):
        self.yaml_file = yaml_file
        self.save_file = save_file
        self.data = self.load_yaml()
        self.modified_data = {}
        self.root = tk.Tk()
        self.root.title("Gestion des Règles")
        self.root.geometry("800x600")
        self.create_widgets()
        self.root.mainloop()

    def load_yaml(self):
        with open(self.yaml_file, "r") as file:
            return yaml.safe_load(file)

    def toggle_apply(self, rule, var, frame):

        self.data[rule["path"]][rule["key"]]["apply"] = var.get()
        self.modified_data.setdefault(rule["path"], {})[rule["key"]] = self.data[rule["path"]][rule["key"]]
        frame.config(bg="red" if not var.get() else "green")

    def create_rule_ui(self, parent, section, rule_key, rule):
        frame = tk.Frame(parent, bd=2, relief=tk.RIDGE, pady=5)
        frame.pack(fill=tk.X, padx=10, pady=5)
        
        label = tk.Label(frame, text=f"{section} - {rule_key}: {rule.get('status', '')}")
        label.pack(side=tk.LEFT, padx=10)
        
        var = tk.BooleanVar(value=rule.get("apply"))
        
        checkbox = ttk.Checkbutton(frame, text="Appliquer", variable=var,
                                   command=lambda: self.toggle_apply({"path": section, "key": rule_key}, var, frame))
        checkbox.pack(side=tk.RIGHT, padx=10)
        checkbox.config(state="disabled" if var.get() else "normal")
        
        frame.config(bg="red" if not var.get() else "green")

    def create_widgets(self):
        self.rule_frame = tk.Frame(self.root)
        self.rule_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        for section, rules in self.data.items():
            for rule_key, rule in rules.items():
                if isinstance(rule, dict) and "apply" in rule:
                    self.create_rule_ui(self.rule_frame, section, rule_key, rule)

        save_button = ttk.Button(self.root, text="Sauvegarder", command=self.save_changes)
        save_button.pack(pady=20)

    def save_changes(self):
        with open(self.save_file, "w") as file:
            yaml.dump(self.modified_data, file, default_flow_style=False, allow_unicode=True)
        print("Modifications sauvegardées")

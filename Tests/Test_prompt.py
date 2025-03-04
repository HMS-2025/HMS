import os
import subprocess
import time
from rich.console import Console
from rich.text import Text
from rich.spinner import Spinner
import contextlib
import io

class CustomTerminal:
    def __init__(self):
        self.console = Console()
        self.prompt = "HMS_TEST > "
        self.commands = {
            "exit": (self.exit_terminal, "Exit the terminal"),
            "clear": (self.clear_screen, "Clear the terminal screen"),
            "help": (self.show_help, "Show available commands"),
            "loader": (self.loader_demo, "Demonstrate the loader animation"),
            "run_analyse_ssh_test": (self.run_analyse_ssh_test, "Run SSH tests"),
            "run_analyse_min_test": (self.run_analyse_min_test, "Run Analyse Min tests"),
            "run_application_ssh_test":(self.run_application_ssh_test ,"Run application tests")
        }
        self.analyse_ssh_test = None
        self.analyse_min_test = None
        self.application_ssh_test= None

    def set_analyse_ssh_test(self, analyse_ssh_test): 
        self.analyse_ssh_test = analyse_ssh_test
    
    def set_application_ssh_test(self, application_ssh_test): 
        self.application_ssh_test = application_ssh_test

    def set_analyse_min_test(self, analyse_min_test): 
        self.analyse_min_test = analyse_min_test
    
    def run(self):
        welcome_text = Text("Welcome to hms test env!\n Help : show the available commands", style="bold magenta blink")
        self.console.print(welcome_text)
        while True:
            try:
                cmd = input(self.prompt).strip()
                if cmd:
                    self.execute_command(cmd)
            except KeyboardInterrupt:
                self.console.print("\nUse 'exit' to quit the terminal.", style="yellow")
            except EOFError:
                self.console.print("\nGoodbye!", style="green")
                break

    def execute_command(self, cmd):
        if cmd in self.commands:
            self.commands[cmd][0]()
        else:
            self.console.print("\nCommand not found\n", style="yellow")

    def execute_system_command(self, cmd):
        try:
            with self.console.status("[cyan]Executing...", spinner="dots"):
                time.sleep(1)  # Simulate processing time
                result = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = result.stdout if result.stdout else result.stderr
                self.console.print(output, style="cyan")
        except Exception as e:
            self.console.print(f"Error executing command: {e}", style="red")

    def loader_demo(self):
        self.console.print("Starting loader demo...", style="bold green")
        with self.console.status("[yellow]Loading...", spinner="dots"):
            time.sleep(2)  # Simulate loading time
        self.console.print("Loader demo completed!", style="bold green")

    def clear_screen(self):
        os.system("clear" if os.name == "posix" else "cls")

    def exit_terminal(self):
        self.console.print("Goodbye!", style="green")
        exit()

    def show_help(self):
        help_text = Text("Available commands:", style="bold blue")
        self.console.print(help_text)
        for cmd, (func, desc) in self.commands.items():
            self.console.print(f" - {cmd}: {desc}", style="blue")
        self.console.print("You can also run system commands.", style="yellow")

    def run_analyse_ssh_test(self): 
        self.console.print("Running SSH tests...", style="bold green")
        with self.console.status("[cyan]Tests in progress...", spinner="dots"):
            self.analyse_ssh_test.run_tests()
        self.console.print("SSH tests completed!", style="bold green")

    def run_analyse_min_test(self): 
        self.console.print("Running Analyse min tests...", style="bold green")
        with self.console.status("[cyan]Tests in progress...", spinner="dots"):
            self.analyse_min_test.run_tests()
        self.console.print("Analyse min tests completed!\nThe script is compatible with your version for the analyse", style="bold green")

    def run_application_ssh_test(self): 
        self.console.print("Running Analyse min tests...", style="bold green")
        with self.console.status("[cyan]Tests in progress...", spinner="dots"):
            self.application_ssh_test.run_tests()
        self.console.print("Analyse min tests completed!\nThe script is compatible with your version for the analyse", style="bold green")
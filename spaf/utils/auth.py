import os
import json
from pathlib import Path
from rich.console import Console

console = Console()

class AuthManager:
    def __init__(self):
        self.config_dir = Path.home() / ".spaf"
        self.config_file = self.config_dir / "auth.json"
        self._ensure_config()

    def _ensure_config(self):
        self.config_dir.mkdir(exist_ok=True)
        if not self.config_file.exists():
            with open(self.config_file, "w") as f:
                json.dump({}, f)

    def login(self, username: str, token: str):
        config = {"username": username, "token": token}
        with open(self.config_file, "w") as f:
            json.dump(config, f)
        console.print(f"[bold green]Success![/bold green] Logged in as [cyan]{username}[/cyan]")

    def get_token(self) -> str:
        with open(self.config_file, "r") as f:
            config = json.load(f)
            return config.get("token")

    def is_logged_in(self) -> bool:
        return bool(self.get_token())

auth_manager = AuthManager()

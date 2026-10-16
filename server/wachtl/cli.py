"""Kommandozeile: ``flask --app wachtl <befehl>``."""
from __future__ import annotations

import os

import click
from flask import Flask

from . import bootstrap, repo
from .services import alertgen, notify


def register(app: Flask) -> None:
    @app.cli.command("init")
    @click.option("--no-reload", is_flag=True, help="vmalert/Alertmanager nicht neu laden (beim ersten Start)")
    def init(no_reload: bool):
        """Datenbank migrieren, Standards anlegen, Regel- und Alertmanager-Datei schreiben, Erst-Admin anlegen."""
        pw = os.environ.get("WACHTL_INITIAL_ADMIN_PASSWORD", "")
        for msg in bootstrap.initialize(admin_password=pw or None, reload=not no_reload):
            click.echo(msg)

    @app.cli.command("create-user")
    @click.argument("username")
    @click.option("--role", type=click.Choice(["admin", "operator", "readonly"]), default="admin")
    @click.password_option()
    def create_user(username: str, role: str, password: str):
        """Benutzer anlegen oder Passwort zurücksetzen (z. B. wenn das Admin-Passwort verloren ging)."""
        try:
            click.echo(f"Benutzer {username} {bootstrap.set_user(username, password, role)}")
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc

    @app.cli.command("regen-rules")
    def regen_rules():
        """vmalert-Regeln und Alertmanager-Konfiguration neu erzeugen und neu laden."""
        click.echo(alertgen.write_rules())
        click.echo(notify.write_config() or "keine Alertmanager-Datei konfiguriert")

    @app.cli.command("prune")
    def prune():
        """Alte Batch-IDs, Audit-Einträge und Alarm-Historie aufräumen."""
        repo.prune()
        click.echo("Aufgeräumt")

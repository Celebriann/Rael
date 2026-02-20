# -*- coding: utf-8 -*-
"""
UI.py — Interface TUI pour le client IRC (Textual)
Installation : pip install textual
Test standalone : python UI.py
"""

import sys
from textual.app import App, ComposeResult
from textual.widgets import Input, RichLog, Label, Button
from textual.containers import Vertical, Horizontal, Container
from textual.screen import Screen
from textual.binding import Binding
from rich.text import Text
from rich.style import Style

# ─── Palette ──────────────────────────────────────────────────────────────────

AMBER        = "#FFB300"
AMBER_DIM    = "#7A5500"
AMBER_BRIGHT = "#FFD54F"
GREEN        = "#69FF47"
CYAN         = "#00E5FF"
RED          = "#FF3D3D"
BG           = "#0A0A0A"
BG_INPUT     = "#111111"
BG_PANEL     = "#0F0F0F"

CSS = f"""
Screen {{
    background: {BG};
}}

/* ── Auth ── */
AuthScreen {{
    align: center middle;
    background: {BG};
}}

#auth_container {{
    align: center middle;
    width: 100%;
    height: 100%;
}}

#auth_box {{
    width: 60;
    height: auto;
    border: solid {AMBER_DIM};
    padding: 1 2;
    background: {BG_PANEL};
}}

#auth_title {{
    text-align: center;
    color: {AMBER_BRIGHT};
    text-style: bold;
    margin-bottom: 1;
}}

#auth_subtitle {{
    text-align: center;
    color: {AMBER_DIM};
    margin-bottom: 1;
}}

.auth_label {{
    color: {AMBER};
    margin-top: 1;
}}

.auth_input {{
    background: {BG_INPUT};
    border: solid {AMBER_DIM};
    color: {AMBER};
}}

.auth_input:focus {{
    border: solid {AMBER};
}}

#auth_buttons {{
    margin-top: 1;
    height: 3;
    align: center middle;
}}

.btn_primary {{
    background: {AMBER_DIM};
    color: {BG};
    border: none;
    margin: 0 1;
}}

.btn_primary:hover {{
    background: {AMBER};
}}

.btn_secondary {{
    background: {BG};
    color: {AMBER_DIM};
    border: solid {AMBER_DIM};
    margin: 0 1;
}}

.btn_secondary:hover {{
    color: {AMBER};
    border: solid {AMBER};
}}

#auth_error {{
    color: {RED};
    text-align: center;
    margin-top: 1;
    height: 1;
}}

/* ── Chat ── */
ChatScreen {{
    layout: vertical;
    background: {BG};
}}

#topbar {{
    height: 1;
    background: {BG_PANEL};
    border-bottom: solid {AMBER_DIM};
    padding: 0 1;
    layout: horizontal;
}}

#status_nick {{
    color: {GREEN};
    width: auto;
}}

#status_sep {{
    color: {AMBER_DIM};
    width: auto;
}}

#status_channel {{
    color: {CYAN};
    width: auto;
}}

#status_tor {{
    color: {AMBER_DIM};
    dock: right;
    width: auto;
}}

#messages {{
    height: 1fr;
    background: {BG};
    padding: 0 1;
    scrollbar-color: {AMBER_DIM};
    scrollbar-background: {BG};
}}

#input_bar {{
    height: 3;
    background: {BG_INPUT};
    border-top: solid {AMBER_DIM};
    layout: horizontal;
    padding: 0 1;
    align: left middle;
}}

#prompt {{
    color: {AMBER_DIM};
    width: auto;
    margin-right: 1;
}}

#msg_input {{
    background: {BG_INPUT};
    border: none;
    color: {AMBER};
    height: 1;
    width: 1fr;
}}

#msg_input:focus {{
    border: none;
}}
"""


# ─── Formatage ────────────────────────────────────────────────────────────────

import re

def format_message(raw: str) -> Text:
    t = Text()
    if raw.startswith("---") and raw.endswith("---"):
        t.append("─" * 4 + " ", style=AMBER_DIM)
        t.append(raw.strip("- "), style=Style(color=AMBER_DIM, italic=True))
        t.append(" " + "─" * 4, style=AMBER_DIM)
        return t
    if raw.startswith("[!]"):
        t.append("⚠ ", style=RED)
        t.append(raw[3:].strip(), style=Style(color=RED, italic=True))
        return t
    if raw.startswith("[*]"):
        t.append("· ", style=AMBER_DIM)
        t.append(raw[3:].strip(), style=AMBER_DIM)
        return t
    if raw.startswith("===") and raw.endswith("==="):
        t.append(raw, style=Style(color=AMBER_BRIGHT, bold=True))
        return t
    m = re.match(r'\[MP (de|a) (.+?)\] (.*)', raw)
    if m:
        direction, who, msg = m.groups()
        t.append("◆ MP ", style=Style(color=AMBER_BRIGHT, bold=True))
        t.append(f"{direction} ", style=AMBER_DIM)
        t.append(who, style=Style(color=GREEN, bold=True))
        t.append(f" {msg}", style=AMBER)
        return t
    m = re.match(r'\[#(.+?)\] (.+?): (.*)', raw)
    if m:
        channel, nick, msg = m.groups()
        t.append("[", style=AMBER_DIM)
        t.append(f"#{channel}", style=Style(color=CYAN, bold=True))
        t.append("] ", style=AMBER_DIM)
        t.append(nick, style=Style(color=GREEN, bold=True))
        t.append(": ", style=AMBER_DIM)
        t.append(msg, style=AMBER)
        return t
    t.append(raw, style=AMBER)
    return t


# ─── Écran d'authentification ─────────────────────────────────────────────────

class AuthScreen(Screen):

    def __init__(self, on_login, on_create):
        super().__init__()
        self._on_login  = on_login
        self._on_create = on_create
        self._mode      = "login"

    def compose(self) -> ComposeResult:
        with Container(id="auth_container"):
            with Vertical(id="auth_box"):
                yield Label("◈  RAEL  ◈ Version 1.2", id="auth_title")
                yield Label("Tor · TLS 1.3 · E2E RSA+AES", id="auth_subtitle")
                yield Label("Pseudo", classes="auth_label")
                yield Input(placeholder="votre_pseudo", id="nick_input", classes="auth_input")
                yield Label("Mot de passe", classes="auth_label")
                yield Input(placeholder="••••••••", password=True, id="pass_input", classes="auth_input")
                yield Label("", id="extra_label", classes="auth_label")
                yield Input(placeholder="", id="extra_input", classes="auth_input")
                with Horizontal(id="auth_buttons"):
                    yield Button("Connexion", id="btn_login", classes="btn_primary")
                    yield Button("Créer un compte", id="btn_switch", classes="btn_secondary")
                yield Label("", id="auth_error")

    def on_mount(self):
        self._set_mode("login")
        self.query_one("#nick_input").focus()

    def _set_mode(self, mode: str):
        self._mode = mode
        extra_label = self.query_one("#extra_label", Label)
        extra_input = self.query_one("#extra_input", Input)
        btn_login   = self.query_one("#btn_login", Button)
        btn_switch  = self.query_one("#btn_switch", Button)
        if mode == "login":
            extra_label.update("")
            extra_input.display = False
            btn_login.label  = "Connexion"
            btn_switch.label = "Créer un compte"
        else:
            extra_label.update("Bio (optionnel)")
            extra_input.display = True
            extra_input.placeholder = "Une courte bio..."
            btn_login.label  = "Créer"
            btn_switch.label = "J'ai déjà un compte"

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn_switch":
            self._set_mode("create" if self._mode == "login" else "login")
            return
        nick  = self.query_one("#nick_input",  Input).value.strip()
        pwd   = self.query_one("#pass_input",  Input).value
        bio   = self.query_one("#extra_input", Input).value.strip()
        error = self.query_one("#auth_error",  Label)
        if not nick:
            error.update("⚠ Le pseudo est obligatoire")
            return
        if not pwd:
            error.update("⚠ Le mot de passe est obligatoire")
            return
        error.update("")
        if self._mode == "login":
            self._on_login(nick, pwd)
        else:
            self._on_create(nick, pwd, bio)

    def on_input_submitted(self, event: Input.Submitted):
        self.query_one("#btn_login", Button).press()

    def show_error(self, msg: str):
        self.query_one("#auth_error", Label).update(f"⚠ {msg}")


# ─── Écran de chat ────────────────────────────────────────────────────────────

class ChatScreen(Screen):

    BINDINGS = [Binding("ctrl+c", "app.quit", "Quitter")]

    def __init__(self, on_send, nick="", tor_active=True):
        super().__init__()
        self._on_send = on_send
        self._nick    = nick
        self._channel = None
        self._tor     = tor_active

    def compose(self) -> ComposeResult:
        with Vertical():
            with Horizontal(id="topbar"):
                yield Label(self._nick or "—", id="status_nick")
                yield Label("  ·  ", id="status_sep")
                yield Label("aucun salon", id="status_channel")
                yield Label("● TOR" if self._tor else "○ LOCAL", id="status_tor")
            yield RichLog(id="messages", highlight=False, markup=False,
                         auto_scroll=True, wrap=True)
            with Horizontal(id="input_bar"):
                yield Label("> ", id="prompt")
                yield Input(placeholder="Tapez un message ou /commande...", id="msg_input")

    def on_mount(self):
        self.query_one("#msg_input").focus()
        self.push_line("[*] Bienvenue ! Tapez /help pour la liste des commandes.")
        self.push_line("[*] Rejoignez un salon avec /join <nom>")

    def on_input_submitted(self, event: Input.Submitted):
        msg = event.value.strip()
        if msg:
            self._on_send(msg)
            self.query_one("#msg_input", Input).value = ""

    def push_line(self, raw: str):
        self.query_one("#messages", RichLog).write(format_message(raw))

    def set_nick(self, nick: str):
        self._nick = nick
        self.query_one("#status_nick", Label).update(nick)

    def set_channel(self, channel):
        self._channel = channel
        ch_label = self.query_one("#status_channel", Label)
        prompt   = self.query_one("#prompt", Label)
        if channel:
            ch_label.update(f"#{channel}")
            prompt.update(Text.assemble(
                (f"#{channel}", Style(color=CYAN, bold=True)),
                (" > ", Style(color=AMBER_DIM))
            ))
        else:
            ch_label.update("aucun salon")
            prompt.update("> ")

    def set_tor_status(self, active: bool):
        self.query_one("#status_tor", Label).update("● TOR" if active else "○ LOCAL")


# ─── Application principale ───────────────────────────────────────────────────

class ChatApp(App):

    CSS = CSS

    def __init__(self, on_auth):
        """
        on_auth(nick, pwd, bio) — appelé quand le formulaire est soumis.
        bio=None si mode connexion, str si création de compte.
        """
        super().__init__()
        self._on_auth     = on_auth
        self._chat_screen = None

    def on_mount(self):
        # Afficher l'écran d'auth au démarrage
        self.push_screen(AuthScreen(
            on_login =lambda n, p:    self._on_auth(n, p, None),
            on_create=lambda n, p, b: self._on_auth(n, p, b)
        ))

    # ── API publique ──────────────────────────────────────────────────────────

    def show_auth_error(self, msg: str):
        """Affiche une erreur sur l'écran d'auth (thread-safe via call_from_thread)."""
        screen = self.screen
        if isinstance(screen, AuthScreen):
            screen.show_error(msg)

    def start_chat(self, nick: str, on_send, tor_active=True):
        """Passe à l'écran de chat (appeler via call_from_thread depuis un thread)."""
        self._chat_screen = ChatScreen(on_send=on_send, nick=nick, tor_active=tor_active)
        # Vider toute la pile sauf l'ecran de base
        while len(self.screen_stack) > 1:
            try:
                self.pop_screen()
            except Exception:
                break
        self.push_screen(self._chat_screen)

    def push_message(self, raw: str):
        if self._chat_screen:
            self._chat_screen.push_line(raw)

    def set_channel(self, channel):
        if self._chat_screen:
            self._chat_screen.set_channel(channel)

    def set_nick(self, nick: str):
        if self._chat_screen:
            self._chat_screen.set_nick(nick)

    def set_tor_status(self, active: bool):
        if self._chat_screen:
            self._chat_screen.set_tor_status(active)

    # Alias pour compatibilité avec client.py
    def auth_error(self, msg: str):
        self.show_auth_error(msg)

    def stop_chat(self):
        pass


# ─── Test standalone ──────────────────────────────────────────────────────────

if __name__ == "__main__":

    def fake_auth(nick, pwd, bio):
        def fake_send(msg):
            app.call_from_thread(
                app.push_message,
                f"[#général] {nick}: {msg}"
            )

        def launch():
            app.start_chat(nick, fake_send, tor_active=False)
            app.push_message(f"[*] Connecté en tant que {nick} (démo)")
            app.set_channel("général")
            app.push_message("[#général] Système: Bienvenue dans le démo !")
            app.push_message("[#général] Alice: Salut 👋")
            app.push_message("[!] Ceci est une erreur exemple")
            app.push_message("--- Séparateur ---")

        app.call_later(0.1, launch)

    app = ChatApp(on_auth=fake_auth)
    app.run()

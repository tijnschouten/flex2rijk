#!/usr/bin/env python3
"""
flex2rijk.py — Automatische login voor flex2rijk.nl Citrix werkplek

Slaat credentials veilig op, vraagt de OneSpan 2FA code interactief op,
en download + opent het ICA bestand.

DISCLAIMER: Deze tool is niet geassocieerd met flex2rijk.nl. Gebruik is op eigen risico.
De auteur biedt geen support en is niet verantwoordelijk voor eventueel verlies van data.
"""

import argparse
import configparser
import contextlib
import getpass
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    import keyring
except ImportError:
    keyring = None  # type: ignore[assignment]

KEYCHAIN_SERVICE = "flex2rijk"
# Absolute paden: een andere 'security' eerder in PATH zou het wachtwoord via stdin
# kunnen onderscheppen.
SECURITY_BIN = "/usr/bin/security"
OPEN_BIN = "/usr/bin/open"
# Exitcode van 'security' voor errSecItemNotFound
SECURITY_ITEM_NOT_FOUND = 44
# Staat in het commentaarveld van items die met een lege lijst vertrouwde apps zijn opgeslagen
CONFIRM_ACCESS_MARKER = "flex2rijk:confirm-access"
# Accountnamen in de Keychain/keyring blijven Engels, anders vindt de tool bestaande items niet
ACCOUNT_LABELS = {"username": "gebruikersnaam", "password": "wachtwoord"}  # nosec B105
LOGIN_URL = "https://www.flex2rijk.nl/logon/LogonPoint/tmindex.html"


# ── Credential helpers (Multi-platform) ───────────────────────────────────────


def keychain_get(account: str) -> str | None:
    """Lees een waarde uit het systeem-credential-beheer; None als die ontbreekt."""
    if platform.system() == "Darwin":
        return _macos_keychain_get(account)
    return _keyring_get(account)


def keychain_set(account: str, password: str, confirm_access: bool = False) -> None:
    """Sla een waarde op in het systeem-credential-beheer.

    Met confirm_access vraagt macOS bij elke uitlezing om toestemming.
    """
    if platform.system() == "Darwin":
        _macos_keychain_set(account, password, confirm_access)
    else:
        _keyring_set(account, password)


def keychain_delete(account: str) -> None:
    """Verwijder een waarde uit het systeem-credential-beheer, als die bestaat."""
    if platform.system() == "Darwin":
        cmd = [SECURITY_BIN, "delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account]
        subprocess.run(cmd, capture_output=True, check=False)  # nosec B603
    else:
        _keyring_delete(account)


def _macos_keychain_get(account: str) -> str | None:
    """Lees een waarde direct uit de macOS Keychain via de 'security' CLI."""
    # Niet -w: dat geeft waarden met niet-ASCII-tekens of een backslash als hex terug,
    # zonder dat je dat aan de uitvoer kunt zien.
    cmd = [SECURITY_BIN, "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-g"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)  # nosec B603
    if result.returncode == SECURITY_ITEM_NOT_FOUND:
        return None
    if result.returncode != 0:
        print(f"[!] Geen toegang tot je {ACCOUNT_LABELS[account]} in de macOS Keychain.")
        return None
    return _parse_security_password(result.stderr)


def _parse_security_password(output: str) -> str:
    """Lees de waarde uit 'password: "..."' of 'password: 0x<hex>  "..."'."""
    line = next(line for line in output.splitlines() if line.startswith("password:"))
    value = line.removeprefix("password:")
    if value.startswith(" 0x"):
        return bytes.fromhex(value[3:].split()[0]).decode()
    return value[2:-1]


def _macos_keychain_attributes(account: str) -> str | None:
    """Lees de kenmerken van een item, of None als het ontbreekt. Leest het geheim niet."""
    cmd = [SECURITY_BIN, "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)  # nosec B603
    return result.stdout if result.returncode == 0 else None


def _macos_keychain_set(account: str, password: str, confirm_access: bool) -> None:
    """Sla een waarde op in de macOS Keychain via de 'security' CLI."""
    # Verwijder eerst om 'already exists' fouten te voorkomen
    keychain_delete(account)

    add_cmd = [SECURITY_BIN, "add-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account]
    if confirm_access:
        # Zonder -T vertrouwt het item /usr/bin/security zelf, en kan elk proces
        # het via 'security find-generic-password' zonder prompt uitlezen.
        add_cmd += ["-T", "", "-j", CONFIRM_ACCESS_MARKER]
    # -w als laatste optie: security leest de waarde (twee keer) van stdin,
    # zodat die niet als argument in de proceslijst staat.
    add_cmd.append("-w")
    result = subprocess.run(  # nosec B603
        add_cmd,
        input=f"{password}\n{password}\n",
        capture_output=True,
        text=True,
        check=False,
        # Met een terminal leest security van de terminal in plaats van stdin
        start_new_session=True,
    )
    if result.returncode != 0:
        print(f"[!] Fout bij opslaan in macOS Keychain: {result.stderr}")
        sys.exit(1)
    print(f"[✓] {ACCOUNT_LABELS[account].capitalize()} opgeslagen in de macOS Keychain.")


def _keyring_get(account: str) -> str | None:
    """Lees een waarde via de 'keyring' bibliotheek (Windows/Linux)."""
    if not keyring:
        print("[!] Keyring-bibliotheek niet gevonden.")
        sys.exit(1)

    try:
        password = keyring.get_password(KEYCHAIN_SERVICE, account)
    except keyring.errors.NoKeyringError:
        return None
    except keyring.errors.KeyringError as e:
        print(f"[!] Geen toegang tot je {ACCOUNT_LABELS[account]} in credential-beheer: {e}")
        return None
    return str(password) if password else None


def _keyring_set(account: str, password: str) -> None:
    """Sla een waarde op via de 'keyring' bibliotheek (Windows/Linux)."""
    if not keyring:
        print("[!] Keyring-bibliotheek niet gevonden.")
        sys.exit(1)

    _require_secure_keyring()
    try:
        keyring.set_password(KEYCHAIN_SERVICE, account, password)
    except (OSError, RuntimeError) as e:
        print(f"[!] Fout bij opslaan in credential-beheer: {e}")
        sys.exit(1)
    print(f"[✓] {ACCOUNT_LABELS[account].capitalize()} opgeslagen in credential-beheer.")


def _require_secure_keyring() -> None:
    """Weiger backends die niets of alles onversleuteld opslaan."""
    backend = keyring.get_keyring()
    # Een ChainerBackend schrijft naar zijn eerste (hoogst geprioriteerde) backend.
    effective = getattr(backend, "backends", [backend])
    # Veilige backends (macOS, Windows, Secret Service, KWallet) hebben prioriteit >= 1;
    # keyrings.alt PlaintextKeyring heeft 0.5, de fail-backend 0.
    if not effective or effective[0].priority < 1:
        print(f"[!] Geen veilige keyring gevonden (backend: {backend}).")
        print("    Installeer een Secret Service (bijv. GNOME Keyring) of KWallet.")
        print("    Zonder opslag log je gewoon in met 'flex2rijk': dan vraagt de tool je gegevens.")
        sys.exit(1)


def _keyring_delete(account: str) -> None:
    """Verwijder een waarde via de 'keyring' bibliotheek (Windows/Linux)."""
    if not keyring:
        return
    with contextlib.suppress(keyring.errors.PasswordDeleteError, keyring.errors.NoKeyringError):
        keyring.delete_password(KEYCHAIN_SERVICE, account)


def setup(store: bool = True) -> None:
    """Interactieve setup: sla credentials op, of verwijder ze met store=False."""
    print("=== Flex2Rijk CLI setup ===")
    if platform.system() == "Linux":
        _remove_plaintext_keyring()
    if store:
        _store_credentials()
    else:
        keychain_delete("username")
        keychain_delete("password")
        print("[✓] Niets opgeslagen. Bij elke login vul je je gebruikersnaam en wachtwoord in.")


def _store_credentials() -> None:
    """Vraag gebruikersnaam en wachtwoord en sla ze op in het systeem-credential-beheer."""
    if platform.system() == "Darwin":
        backend = "macOS Keychain"
    else:
        # Controleer voordat de gebruiker iets intypt
        _require_secure_keyring()
        backend = "System Keyring"
    print(f"Gebruikt backend: {backend}")
    print(f"Credentials worden opgeslagen onder service: '{KEYCHAIN_SERVICE}'\n")

    username = input("Gebruikersnaam (bijv. RWS\\tijn.example of e-mailadres): ").strip()
    keychain_set("username", username)
    password = getpass.getpass("Wachtwoord: ")
    keychain_set("password", password, confirm_access=True)
    if platform.system() == "Darwin":
        print("[i] Bij elke login vraagt macOS om toegang tot je wachtwoord. In dat venster")
        print("    staat 'security': het programma waarmee de Flex2Rijk CLI de Keychain leest.")
    print("\n[✓] Setup klaar. Start de login met: flex2rijk")


def _remove_plaintext_keyring() -> None:
    """Verwijder wat versie 0.1.0 via keyrings.alt onversleuteld opsloeg."""
    data_home = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    path = Path(data_home) / "python_keyring" / "keyring_pass.cfg"
    # Het bestand is gedeeld met andere programma's: alleen de eigen sectie gaat eruit.
    config = configparser.RawConfigParser()
    if not config.read(path) or not config.remove_section(KEYCHAIN_SERVICE):
        return
    with path.open("w") as f:
        config.write(f)
    print(f"[✓] Onversleutelde gegevens van de Flex2Rijk CLI verwijderd uit {path}")


# ── Citrix ICA download ───────────────────────────────────────────────────────


def _open_ica_macos(path: Path) -> None:
    """Open het ICA bestand op macOS met subprocess.Popen."""
    with subprocess.Popen([OPEN_BIN, str(path.absolute())]) as _:  # nosec B603
        pass


def _open_ica_windows(path: Path) -> None:
    """Open het ICA bestand op Windows."""
    if hasattr(os, "startfile"):
        os.startfile(str(path.absolute()))  # nosec B606
    else:
        print("[!] os.startfile niet beschikbaar op dit systeem.")


def _open_ica_linux(path: Path) -> None:
    """Open het ICA bestand op Linux met subprocess.Popen."""
    # xdg-open staat per distributie op een ander pad
    with subprocess.Popen(["xdg-open", str(path.absolute())]) as _:  # nosec B603, B607
        pass


def _dispatch_open(current_os: str, path: Path) -> None:
    """Stuur het openen van het bestand naar de juiste OS-functie."""
    if current_os == "darwin":
        _open_ica_macos(path)
    elif current_os == "windows":
        _open_ica_windows(path)
    else:
        _open_ica_linux(path)


def open_ica(path: Path) -> None:
    """Open het ICA bestand met Citrix Workspace op een cross-platform manier."""
    if not path.exists():
        print(f"[!] Fout: ICA bestand niet gevonden op {path}")
        return

    print(f"[→] ICA bestand openen: {path}")
    current_os = platform.system().lower()
    try:
        _dispatch_open(current_os, path)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"[!] Kon ICA bestand niet automatisch openen: {e}")
        print(f"    Open het bestand handmatig: {path}")


# ── Login flow ────────────────────────────────────────────────────────────────


def _read_password() -> str:
    """Lees het opgeslagen wachtwoord, of vraag erom als het niet is opgeslagen of geweigerd."""
    if platform.system() == "Darwin":
        attributes = _macos_keychain_attributes("password")
        if attributes is not None and CONFIRM_ACCESS_MARKER not in attributes:
            return _migrate_macos_password() or getpass.getpass("Wachtwoord: ")
        if attributes is not None:
            print("[i] macOS vraagt zo om toegang tot je wachtwoord. Kies 'Sta toe'.")
            print("    Met 'Sta altijd toe' kan elk programma het voortaan zonder vragen lezen.")
    return keychain_get("password") or getpass.getpass("Wachtwoord: ")


def _migrate_macos_password() -> str | None:
    """Sla een wachtwoord van versie 0.1.0, dat elk proces kon lezen, opnieuw op."""
    # Het oude item vertrouwt 'security', dus dit lezen geeft nog geen dialoog.
    password = _macos_keychain_get("password")
    if password:
        keychain_set("password", password, confirm_access=True)
        print("[✓] Wachtwoord beveiligd: macOS vraagt vanaf de volgende login om toestemming.")
    return password


def login(headless: bool = True, otp: str | None = None) -> None:
    """Voer de volledige login-flow uit."""
    username = keychain_get("username") or input("Gebruikersnaam: ").strip()
    password = _read_password()

    print(f"[✓] Credentials geladen voor: {username}")

    with tempfile.TemporaryDirectory(prefix="flex2rijk_") as download_dir:
        ica_path = _run_browser(headless, username, password, otp, Path(download_dir))

        if ica_path:
            open_ica(ica_path)
            print("[✓] Klaar! Citrix Workspace wordt geopend.")
            # Geef de applicatie de tijd om het bestand te laden voordat de map verdwijnt
            time.sleep(15)
        else:
            print("[!] Geen ICA bestand gevonden.")


def _run_browser(
    headless: bool, username: str, password: str, otp: str | None, download_dir: Path
) -> Path | None:
    """Start de browser en voer de login uit."""
    _ensure_playwright_browsers()

    from playwright.sync_api import sync_playwright  # noqa: PLC0415

    print("[→] Browser starten...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(accept_downloads=True)
        page = context.new_page()

        _perform_page_login(page, username, password, otp)

        print("[→] Wachten op Citrix sessie / ICA download...")
        ica_path = _wait_for_ica(page, download_dir)

        browser.close()
        return ica_path


def _ensure_playwright_browsers() -> None:
    """Controleer of Playwright browsers zijn geïnstalleerd, installeer ze zo niet."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: PLC0415

        with sync_playwright() as p:
            # Probeer browser te starten om te checken of deze er is
            browser = p.chromium.launch()
            browser.close()
    except (ImportError, Exception):  # noqa: BLE001
        print("[→] Playwright browser (Chromium) niet gevonden. Installeren...")
        # Installeer alleen chromium (is sneller en kleiner dan alles)
        cmd = [sys.executable, "-m", "playwright", "install", "chromium"]
        subprocess.run(cmd, check=True)  # nosec B603
        print("[✓] Chromium succesvol geïnstalleerd.")


def _perform_page_login(page: Any, username: str, password: str, otp: str | None) -> None:
    """Navigeer naar de loginpagina en vul de gegevens in."""
    print(f"[→] Navigeren naar {LOGIN_URL}")
    page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=60000)

    print("[→] Wachten op loginformulier...")
    page.get_by_role("textbox", name="User name:").wait_for(state="visible", timeout=15000)

    print("[→] Gebruikersnaam invullen...")
    page.get_by_role("textbox", name="User name:").fill(username)

    print("[→] Wachtwoord invullen...")
    page.get_by_role("textbox", name="Password:").fill(password)

    if not otp:
        print("\n" + "=" * 50)
        otp = input("🔐 Voer je OneSpan token in: ").strip()
        print("=" * 50 + "\n")

    print("[→] Token invullen...")
    page.get_by_role("textbox", name="Token:").fill(otp)

    print("[→] Log On klikken...")
    page.get_by_role("link", name="Log On").click()


# ── Page interaction helpers ──────────────────────────────────────────────────


def _wait_for_ica(page: Any, download_dir: Path) -> Path | None:
    """Wacht tot de login redirect naar de store leidt en vang de ICA download op."""
    from playwright.sync_api import TimeoutError as PWTimeout  # noqa: PLC0415

    print("[→] Wachten op detectiepagina...")
    try:
        # 1. Klik op detectie
        _handle_detect_button(page)

        # 2. Klik op 'Already installed' en vang download op
        with page.expect_download(timeout=20000) as dl_info:
            _handle_install_button(page)

        download = dl_info.value
        # Vaste naam: met de naam van de server kiest die het pad en de extensie,
        # en 'open' start het bestand met de app die bij die extensie hoort.
        ica_path = download_dir / "session.ica"
        download.save_as(str(ica_path))

        print(f"[✓] ICA succesvol gedownload naar: {ica_path}")
        return ica_path
    except PWTimeout:
        print("[!] Timeout tijdens wachten op ICA download.")
        # mkstemp: uniek pad, alleen leesbaar voor de gebruiker (de pagina toont mogelijk
        # gegevens van na de login)
        fd, screenshot = tempfile.mkstemp(prefix="flex2rijk_ica_timeout_", suffix=".png")
        os.close(fd)
        page.screenshot(path=screenshot)
        print(f"    Screenshot: {screenshot}")
        return None


def _handle_detect_button(page: Any) -> None:
    """Klik op de 'Detect Citrix Workspace app' knop."""
    try:
        detect = page.get_by_role("link", name="Detect Citrix Workspace app")
        detect.wait_for(state="visible", timeout=15000)
        print("[→] 'Detect Citrix Workspace app' gevonden, klikken...")
        detect.click()
    except Exception:  # noqa: BLE001  # nosec B110
        # Knop wellicht niet aanwezig, negeer en ga door naar volgende stap
        pass


def _handle_install_button(page: Any) -> None:
    """Klik op de 'Already installed' knop."""
    installed = page.get_by_role("link", name="Already installed")
    installed.wait_for(state="visible", timeout=10000)
    print("[→] 'Already installed' gevonden, klikken...")
    installed.click()


# ── Entrypoint ────────────────────────────────────────────────────────────────


def main() -> None:
    """Main entrypoint voor de CLI."""
    parser = argparse.ArgumentParser(
        description="Flex2Rijk CLI: automatische login op flex2rijk.nl"
    )
    parser.add_argument("token", nargs="?", help="OneSpan token")
    parser.add_argument("--setup", action="store_true", help="Sla credentials op")
    parser.add_argument("--no-headless", action="store_true", help="Toon de browser")
    parser.add_argument(
        "--no-store",
        action="store_true",
        help="Sla bij --setup niets op en verwijder opgeslagen gegevens",
    )
    args = parser.parse_args()

    if args.no_store and not args.setup:
        parser.error("--no-store werkt alleen samen met --setup")
    if args.setup:
        setup(store=not args.no_store)
    else:
        login(headless=not args.no_headless, otp=args.token)


if __name__ == "__main__":
    main()

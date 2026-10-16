# Changelog

Alle noemenswaardige wijzigingen in de Flex2Rijk CLI. De opmaak volgt [Keep a Changelog](https://keepachangelog.com/nl/1.1.0/) en de versienummers volgen [Semantic Versioning](https://semver.org/lang/nl/).

## 0.2.0 - nog niet uitgebracht

Deze versie dicht de manieren waarop je wachtwoord kon uitlekken of een onbetrouwbaar bestand kon starten.

### Beveiliging

- **macOS:** het wachtwoord ging als argument naar `security` en stond zo in de proceslijst. Het gaat nu via stdin.
- **macOS:** elk proces kon het opgeslagen wachtwoord zonder vragen uitlezen. Nu vraagt macOS bij elke login om toestemming. Een wachtwoord uit 0.1.0 zet de eerstvolgende login vanzelf om.
- **Linux:** zonder Secret Service sloeg 0.1.0 het wachtwoord onversleuteld (base64) op in `~/.local/share/python_keyring/keyring_pass.cfg`. De tool weigert nu onveilige opslag, en `--setup` haalt het oude wachtwoord uit dat bestand.
- Het ICA-bestand kreeg de naam die de server voorstelde. Een vervalste server kon zo het pad of een extensie kiezen die bij het openen iets uitvoert. Het bestand heet nu altijd `session.ica`.
- De screenshot bij een time-out komt in een privébestand in plaats van op een vast pad in `/tmp`.
- `security` en `open` worden met hun volledige pad aangeroepen, zodat een ander programma met dezelfde naam in je `PATH` het wachtwoord niet kan onderscheppen.
- Playwright gaat van minimaal 1.40 naar 1.63. Alle dependencies staan op een vaste versie.

### Gewijzigd

- `--setup --no-store` slaat niets meer op en verwijdert eerder opgeslagen gegevens. Wat niet is opgeslagen, vraagt de tool bij het inloggen, dus `--setup` is optioneel.
- Weiger je in het macOS-venster de toegang, dan vraagt de tool om je wachtwoord in plaats van te stoppen.
- `--setup` legt uit dat het macOS-venster om toegang vraagt namens `security`.
- Ruff vervangt Pylint.
- De README en de meldingen noemen de tool Flex2Rijk CLI. Het commando blijft `flex2rijk`.

### Opgelost

- Op macOS kwam een wachtwoord met niet-ASCII-tekens of een backslash als hex terug, en verdwenen spaties aan het begin of eind.

### Toegevoegd

- Tests met 100% regel- en branch-coverage, afgedwongen in de CI.
- pre-commit met officiële hooks: Ruff, mypy, Bandit, gitleaks, actionlint en zizmor.
- Dependabot en een pip-audit-controle in de CI.

### Verwijderd

- De dependency `keyrings-alt`. Die gaf `keyring` extra opslagmethoden, waaronder een onversleuteld bestand. Zonder Secret Service koos `keyring` dat bestand.
- Ongebruikte fallback-functies voor de loginknop.

## 0.1.0 - 2026-03-28

Eerste release.

### Toegevoegd

- Login op flex2rijk.nl met Playwright: de tool vult gebruikersnaam, wachtwoord en OneSpan-token in, downloadt het ICA-bestand en opent het in Citrix Workspace.
- `--setup` slaat gebruikersnaam en wachtwoord op in de macOS Keychain, of via `keyring` in Windows Credential Manager of de Linux Secret Service.
- Het OneSpan-token geef je mee als argument (`flex2rijk 123456`) of vul je in als de tool erom vraagt.
- `--no-headless` toont de browser.
- Bij de eerste start installeert de tool Chromium automatisch.
- Werkt op macOS, Windows en Linux.
- Publicatie op PyPI via GitHub Actions.

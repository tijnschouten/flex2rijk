"""Unit tests voor flex2rijk CLI."""

import importlib
import os
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import keyring.errors
import pytest
from playwright.sync_api import TimeoutError as PWTimeout

from flex2rijk import cli


def _run_result(returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# ── Import ────────────────────────────────────────────────────────────────────


def test_keyring_import_ontbreekt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test dat een ontbrekende keyring-bibliotheek None oplevert."""
    monkeypatch.setitem(sys.modules, "keyring", None)
    try:
        importlib.reload(cli)
        assert vars(cli)["keyring"] is None
    finally:
        monkeypatch.undo()
        importlib.reload(cli)
    assert vars(cli)["keyring"] is not None


# ── Dispatch per platform ─────────────────────────────────────────────────────


def test_keychain_get_macos(mocker: Any) -> None:
    """Test ophalen op macOS."""
    mocker.patch("platform.system", return_value="Darwin")
    mock_get = mocker.patch("flex2rijk.cli._macos_keychain_get", return_value="x")
    assert cli.keychain_get("username") == "x"
    mock_get.assert_called_once_with("username")


def test_keychain_get_linux(mocker: Any) -> None:
    """Test ophalen op Linux."""
    mocker.patch("platform.system", return_value="Linux")
    mock_get = mocker.patch("flex2rijk.cli._keyring_get", return_value="x")
    assert cli.keychain_get("username") == "x"
    mock_get.assert_called_once_with("username")


def test_keychain_set_macos(mocker: Any) -> None:
    """Test opslaan op macOS geeft confirm_access door."""
    mocker.patch("platform.system", return_value="Darwin")
    mock_set = mocker.patch("flex2rijk.cli._macos_keychain_set")
    cli.keychain_set("password", "s", confirm_access=True)
    mock_set.assert_called_once_with("password", "s", True)


def test_keychain_set_linux(mocker: Any) -> None:
    """Test opslaan op Linux."""
    mocker.patch("platform.system", return_value="Linux")
    mock_set = mocker.patch("flex2rijk.cli._keyring_set")
    cli.keychain_set("password", "s", confirm_access=True)
    mock_set.assert_called_once_with("password", "s")


def test_keychain_delete_macos(mocker: Any) -> None:
    """Test verwijderen op macOS via security."""
    mocker.patch("platform.system", return_value="Darwin")
    mock_run = mocker.patch("subprocess.run")
    cli.keychain_delete("password")
    mock_run.assert_called_once_with(
        ["/usr/bin/security", "delete-generic-password", "-s", "flex2rijk", "-a", "password"],
        capture_output=True,
        check=False,
    )


def test_keychain_delete_linux(mocker: Any) -> None:
    """Test verwijderen op Linux."""
    mocker.patch("platform.system", return_value="Linux")
    mock_delete = mocker.patch("flex2rijk.cli._keyring_delete")
    cli.keychain_delete("password")
    mock_delete.assert_called_once_with("password")


# ── macOS Keychain ────────────────────────────────────────────────────────────


def test_macos_keychain_get_succes(mocker: Any) -> None:
    """Test dat returncode 0 het wachtwoord uit de -g uitvoer geeft."""
    result = _run_result(0, stderr='password: " geheim "\n')
    mock_run = mocker.patch("subprocess.run", return_value=result)
    assert cli._macos_keychain_get("password") == " geheim "
    mock_run.assert_called_once_with(
        ["/usr/bin/security", "find-generic-password", "-s", "flex2rijk", "-a", "password", "-g"],
        capture_output=True,
        text=True,
        check=False,
    )


def test_macos_keychain_get_niet_gevonden(mocker: Any) -> None:
    """Test dat returncode 44 None geeft."""
    mocker.patch("subprocess.run", return_value=_run_result(44))
    assert cli._macos_keychain_get("password") is None


@pytest.mark.parametrize("returncode", [1, 36, 128])
def test_macos_keychain_get_andere_fout(
    mocker: Any, capsys: pytest.CaptureFixture[str], returncode: int
) -> None:
    """Test dat een geweigerde of mislukte uitlezing None geeft met een melding."""
    mocker.patch("subprocess.run", return_value=_run_result(returncode))
    assert cli._macos_keychain_get("password") is None
    assert "Geen toegang tot je wachtwoord" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ('password: "geheim"', "geheim"),
        ('password: "  spaties rond  "', "  spaties rond  "),
        ('password: "4142"', "4142"),
        ('password: "a"b"', 'a"b'),
        ('password: 0x476568E282AC  "Geh\\342\\202\\254"', "Geh€"),
        ('password: 0x615C62  "a\\134b"', "a\\b"),
        ("password:", ""),
        ('keychain: "/x"\npassword: "na andere regel"\n', "na andere regel"),
    ],
)
def test_parse_security_password(output: str, expected: str) -> None:
    """Test de uitvoer van 'security -g', ook als die hex is."""
    assert cli._parse_security_password(output) == expected


def test_macos_keychain_set_met_bevestiging(mocker: Any) -> None:
    """Test dat het wachtwoord via stdin gaat, -w laatste is en -T aanwezig is."""
    secret = "S3cr3t!"
    mock_delete = mocker.patch("flex2rijk.cli.keychain_delete")
    mock_run = mocker.patch("subprocess.run", return_value=_run_result(0))
    cli._macos_keychain_set("password", secret, confirm_access=True)

    mock_delete.assert_called_once_with("password")
    mock_run.assert_called_once()
    argv = mock_run.call_args.args[0]
    assert argv == [
        "/usr/bin/security",
        "add-generic-password",
        "-s",
        "flex2rijk",
        "-a",
        "password",
        "-T",
        "",
        "-j",
        "flex2rijk:confirm-access",
        "-w",
    ]
    assert argv[-1] == "-w"
    assert all(secret not in arg for arg in argv)
    assert mock_run.call_args.kwargs["input"] == f"{secret}\n{secret}\n"
    assert mock_run.call_args.kwargs["start_new_session"] is True


def test_macos_keychain_set_zonder_bevestiging(mocker: Any) -> None:
    """Test dat zonder confirm_access geen -T wordt meegegeven."""
    secret = "S3cr3t!"
    mocker.patch("flex2rijk.cli.keychain_delete")
    mock_run = mocker.patch("subprocess.run", return_value=_run_result(0))
    cli._macos_keychain_set("username", secret, confirm_access=False)

    argv = mock_run.call_args.args[0]
    assert "-T" not in argv
    assert "-j" not in argv
    assert argv[-1] == "-w"
    assert secret not in " ".join(argv)
    assert mock_run.call_args.kwargs["input"] == f"{secret}\n{secret}\n"
    assert mock_run.call_args.kwargs["start_new_session"] is True


def test_macos_keychain_set_verwijdert_eerst(mocker: Any) -> None:
    """Test dat het bestaande item eerst wordt verwijderd, daarna toegevoegd."""
    mocker.patch("platform.system", return_value="Darwin")
    mock_run = mocker.patch("subprocess.run", return_value=_run_result(0))
    cli._macos_keychain_set("password", "x", confirm_access=True)

    first, second = mock_run.call_args_list
    assert first.args[0][1] == "delete-generic-password"
    assert second.args[0][1] == "add-generic-password"


def test_macos_keychain_set_fout(mocker: Any) -> None:
    """Test dat een mislukte add afsluit met exitcode 1."""
    mocker.patch("flex2rijk.cli.keychain_delete")
    mocker.patch("subprocess.run", return_value=_run_result(1, stderr="boom"))
    with pytest.raises(SystemExit) as exc:
        cli._macos_keychain_set("password", "x", confirm_access=True)
    assert exc.value.code == 1


# ── keyring (Windows/Linux) ───────────────────────────────────────────────────


def test_keyring_get_zonder_bibliotheek(mocker: Any) -> None:
    """Test dat een ontbrekende keyring afsluit."""
    mocker.patch("flex2rijk.cli.keyring", None)
    with pytest.raises(SystemExit) as exc:
        cli._keyring_get("username")
    assert exc.value.code == 1


def test_keyring_get_gevonden(mocker: Any) -> None:
    """Test ophalen van een bestaande waarde."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.get_password.return_value = "geheim"
    assert cli._keyring_get("username") == "geheim"
    mock_keyring.get_password.assert_called_once_with("flex2rijk", "username")


def test_keyring_get_ontbreekt(mocker: Any) -> None:
    """Test dat een ontbrekende waarde None geeft."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.get_password.return_value = None
    assert cli._keyring_get("username") is None


def test_keyring_get_zonder_keyring(mocker: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """Test dat een systeem zonder keyring None geeft, zonder melding."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.errors = keyring.errors
    mock_keyring.get_password.side_effect = keyring.errors.NoKeyringError()
    assert cli._keyring_get("username") is None
    assert capsys.readouterr().out == ""


def test_keyring_get_fout(mocker: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """Test dat een geweigerde uitlezing None geeft met een melding."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.errors = keyring.errors
    mock_keyring.get_password.side_effect = keyring.errors.KeyringLocked("op slot")
    assert cli._keyring_get("password") is None
    assert "Geen toegang tot je wachtwoord" in capsys.readouterr().out


def test_keyring_set_zonder_bibliotheek(mocker: Any) -> None:
    """Test dat opslaan zonder keyring afsluit."""
    mocker.patch("flex2rijk.cli.keyring", None)
    with pytest.raises(SystemExit) as exc:
        cli._keyring_set("username", "x")
    assert exc.value.code == 1


def test_keyring_set_controleert_backend_voor_opslaan(mocker: Any) -> None:
    """Test dat _require_secure_keyring voor set_password wordt aangeroepen."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    manager = mocker.Mock()
    manager.attach_mock(mocker.patch("flex2rijk.cli._require_secure_keyring"), "require")
    manager.attach_mock(mock_keyring.set_password, "set_password")

    cli._keyring_set("username", "x")

    assert [c[0] for c in manager.mock_calls] == ["require", "set_password"]
    mock_keyring.set_password.assert_called_once_with("flex2rijk", "username", "x")


def test_keyring_set_weigert_onveilige_backend(mocker: Any) -> None:
    """Test dat bij een onveilige backend niets wordt opgeslagen."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.get_keyring.return_value = SimpleNamespace(priority=0.5)
    with pytest.raises(SystemExit) as exc:
        cli._keyring_set("username", "x")
    assert exc.value.code == 1
    mock_keyring.set_password.assert_not_called()


def test_keyring_set_fout(mocker: Any) -> None:
    """Test dat een fout bij opslaan afsluit."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mocker.patch("flex2rijk.cli._require_secure_keyring")
    mock_keyring.set_password.side_effect = OSError("kapot")
    with pytest.raises(SystemExit) as exc:
        cli._keyring_set("username", "x")
    assert exc.value.code == 1


def test_keyring_set_succes(mocker: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """Test de melding na succesvol opslaan."""
    mocker.patch("flex2rijk.cli.keyring")
    mocker.patch("flex2rijk.cli._require_secure_keyring")
    cli._keyring_set("username", "x")
    assert "Gebruikersnaam opgeslagen in credential-beheer" in capsys.readouterr().out


@pytest.mark.parametrize("priority", [0.5, 0])
def test_require_secure_keyring_weigert_lage_prioriteit(mocker: Any, priority: float) -> None:
    """Test dat plaintext (0.5) en fail (0) backends worden geweigerd."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.get_keyring.return_value = SimpleNamespace(priority=priority)
    with pytest.raises(SystemExit) as exc:
        cli._require_secure_keyring()
    assert exc.value.code == 1


def test_require_secure_keyring_weigert_lege_chainer(mocker: Any) -> None:
    """Test dat een chainer zonder backends wordt geweigerd."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.get_keyring.return_value = SimpleNamespace(priority=10, backends=[])
    with pytest.raises(SystemExit) as exc:
        cli._require_secure_keyring()
    assert exc.value.code == 1


def test_require_secure_keyring_weigert_onveilige_chainer(mocker: Any) -> None:
    """Test dat een chainer met een eerste backend met prioriteit < 1 wordt geweigerd."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.get_keyring.return_value = SimpleNamespace(
        priority=10, backends=[SimpleNamespace(priority=0.5), SimpleNamespace(priority=5)]
    )
    with pytest.raises(SystemExit) as exc:
        cli._require_secure_keyring()
    assert exc.value.code == 1


def test_require_secure_keyring_accepteert_veilige_backend(mocker: Any) -> None:
    """Test dat een backend met prioriteit >= 1 wordt geaccepteerd."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.get_keyring.return_value = SimpleNamespace(priority=1)
    cli._require_secure_keyring()


def test_require_secure_keyring_accepteert_chainer(mocker: Any) -> None:
    """Test dat een chainer met veilige eerste backend wordt geaccepteerd."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.get_keyring.return_value = SimpleNamespace(
        priority=10, backends=[SimpleNamespace(priority=5), SimpleNamespace(priority=0.5)]
    )
    cli._require_secure_keyring()


def test_keyring_delete_zonder_bibliotheek(mocker: Any) -> None:
    """Test dat verwijderen zonder keyring niets doet."""
    mocker.patch("flex2rijk.cli.keyring", None)
    cli._keyring_delete("password")


def test_keyring_delete_succes(mocker: Any) -> None:
    """Test verwijderen via keyring."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    cli._keyring_delete("password")
    mock_keyring.delete_password.assert_called_once_with("flex2rijk", "password")


def test_keyring_delete_bestaat_niet(mocker: Any) -> None:
    """Test dat een ontbrekend item wordt genegeerd."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.errors = keyring.errors
    mock_keyring.delete_password.side_effect = keyring.errors.PasswordDeleteError()
    cli._keyring_delete("password")


def test_keyring_delete_zonder_keyring(mocker: Any) -> None:
    """Test dat verwijderen op een systeem zonder keyring niets doet."""
    mock_keyring = mocker.patch("flex2rijk.cli.keyring")
    mock_keyring.errors = keyring.errors
    mock_keyring.delete_password.side_effect = keyring.errors.NoKeyringError()
    cli._keyring_delete("password")


# ── Setup ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("system", ["Darwin", "Linux"])
def test_setup_slaat_op(mocker: Any, capsys: pytest.CaptureFixture[str], system: str) -> None:
    """Test dat setup gebruikersnaam en wachtwoord opslaat, het wachtwoord met confirm_access."""
    mocker.patch("platform.system", return_value=system)
    mocker.patch("builtins.input", return_value="  gebruiker  ")
    mock_getpass = mocker.patch("getpass.getpass", return_value="geheim")
    mock_set = mocker.patch("flex2rijk.cli.keychain_set")
    mock_delete = mocker.patch("flex2rijk.cli.keychain_delete")
    mock_cleanup = mocker.patch("flex2rijk.cli._remove_plaintext_keyring")
    mock_guard = mocker.patch("flex2rijk.cli._require_secure_keyring")

    cli.setup(store=True)

    mock_getpass.assert_called_once()
    assert mock_set.call_args_list == [
        mocker.call("username", "gebruiker"),
        mocker.call("password", "geheim", confirm_access=True),
    ]
    mock_delete.assert_not_called()
    assert ("staat 'security'" in capsys.readouterr().out) is (system == "Darwin")
    assert mock_cleanup.called is (system == "Linux")
    assert mock_guard.called is (system == "Linux")


def test_setup_controleert_keyring_voor_invoer(mocker: Any) -> None:
    """Test dat setup zonder veilige keyring stopt voordat er iets wordt gevraagd."""
    mocker.patch("platform.system", return_value="Linux")
    mocker.patch("flex2rijk.cli._remove_plaintext_keyring")
    mocker.patch("flex2rijk.cli._require_secure_keyring", side_effect=SystemExit(1))
    mock_input = mocker.patch("builtins.input")

    with pytest.raises(SystemExit):
        cli.setup(store=True)
    mock_input.assert_not_called()


@pytest.mark.parametrize("system", ["Darwin", "Linux"])
def test_setup_zonder_opslag(mocker: Any, system: str) -> None:
    """Test dat setup met store=False niets vraagt en alles verwijdert."""
    mocker.patch("platform.system", return_value=system)
    mock_input = mocker.patch("builtins.input")
    mock_getpass = mocker.patch("getpass.getpass")
    mock_set = mocker.patch("flex2rijk.cli.keychain_set")
    mock_delete = mocker.patch("flex2rijk.cli.keychain_delete")
    mock_cleanup = mocker.patch("flex2rijk.cli._remove_plaintext_keyring")

    cli.setup(store=False)

    mock_input.assert_not_called()
    mock_getpass.assert_not_called()
    mock_set.assert_not_called()
    assert mock_delete.call_args_list == [mocker.call("username"), mocker.call("password")]
    assert mock_cleanup.called is (system == "Linux")


_PLAINTEXT = "[flex2rijk]\npassword = \n\tZ2VoZWlt\n\n[ander_2Dprogramma]\nuser = \n\tYmxpamY=\n"


def test_remove_plaintext_keyring(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test dat alleen de eigen sectie uit het gedeelde bestand verdwijnt."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    path = tmp_path / "python_keyring" / "keyring_pass.cfg"
    path.parent.mkdir()
    path.write_text(_PLAINTEXT)

    cli._remove_plaintext_keyring()

    content = path.read_text()
    assert "flex2rijk" not in content
    assert "[ander_2Dprogramma]" in content
    assert "YmxpamY=" in content
    assert "verwijderd uit" in capsys.readouterr().out


def test_remove_plaintext_keyring_standaardpad(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Test het pad onder ~/.local/share zonder XDG_DATA_HOME."""
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path / ".local" / "share" / "python_keyring" / "keyring_pass.cfg"
    path.parent.mkdir(parents=True)
    path.write_text(_PLAINTEXT)

    cli._remove_plaintext_keyring()

    assert "flex2rijk" not in path.read_text()


@pytest.mark.parametrize("content", [None, "[ander_2Dprogramma]\nuser = \n\tYmxpamY=\n"])
def test_remove_plaintext_keyring_niets_te_doen(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    content: str | None,
) -> None:
    """Test dat een ontbrekend bestand of een bestand zonder eigen sectie blijft zoals het is."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    path = tmp_path / "python_keyring" / "keyring_pass.cfg"
    if content is not None:
        path.parent.mkdir()
        path.write_text(content)

    cli._remove_plaintext_keyring()

    assert path.exists() is (content is not None)
    if content is not None:
        assert path.read_text() == content
    assert capsys.readouterr().out == ""


# ── ICA openen ────────────────────────────────────────────────────────────────


def test_open_ica_macos(mocker: Any) -> None:
    """Test openen van ICA op macOS."""
    mocker.patch("platform.system", return_value="Darwin")
    mock_popen = mocker.patch("subprocess.Popen")
    mocker.patch.object(Path, "exists", return_value=True)

    path = Path("/tmp/test.ica")
    cli.open_ica(path)

    mock_popen.assert_called_once_with(["/usr/bin/open", str(path.absolute())])


def test_open_ica_windows(mocker: Any) -> None:
    """Test openen van ICA op Windows."""
    mocker.patch("platform.system", return_value="Windows")
    mock_startfile = mocker.patch("os.startfile", create=True)
    mocker.patch.object(Path, "exists", return_value=True)

    path = Path("C:/temp/test.ica")
    cli.open_ica(path)

    mock_startfile.assert_called_once_with(str(path.absolute()))


def test_open_ica_windows_zonder_startfile(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test Windows zonder os.startfile."""
    monkeypatch.delattr(os, "startfile", raising=False)
    cli._open_ica_windows(Path("test.ica"))
    assert "os.startfile niet beschikbaar" in capsys.readouterr().out


def test_open_ica_linux(mocker: Any) -> None:
    """Test openen van ICA op Linux."""
    mocker.patch("platform.system", return_value="Linux")
    mock_popen = mocker.patch("subprocess.Popen")
    mocker.patch.object(Path, "exists", return_value=True)

    path = Path("/tmp/test.ica")
    cli.open_ica(path)

    mock_popen.assert_called_once_with(["xdg-open", str(path.absolute())])


def test_open_ica_bestand_ontbreekt(mocker: Any) -> None:
    """Test dat een ontbrekend bestand niets opent."""
    mock_dispatch = mocker.patch("flex2rijk.cli._dispatch_open")
    cli.open_ica(Path("/niet/aanwezig.ica"))
    mock_dispatch.assert_not_called()


def test_open_ica_fout_bij_openen(mocker: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """Test dat een fout bij openen wordt afgevangen."""
    mocker.patch("platform.system", return_value="Linux")
    mocker.patch.object(Path, "exists", return_value=True)
    mocker.patch("flex2rijk.cli._dispatch_open", side_effect=subprocess.SubprocessError("nee"))

    cli.open_ica(Path("/tmp/test.ica"))

    assert "Open het bestand handmatig" in capsys.readouterr().out


# ── Login ─────────────────────────────────────────────────────────────────────


def _patch_login(mocker: Any, ica: Path | None) -> dict[str, Any]:
    return {
        "run_browser": mocker.patch("flex2rijk.cli._run_browser", return_value=ica),
        "open_ica": mocker.patch("flex2rijk.cli.open_ica"),
        "sleep": mocker.patch("time.sleep"),
        "getpass": mocker.patch("getpass.getpass", return_value="getypt"),
        "attributes": mocker.patch("flex2rijk.cli._macos_keychain_attributes", return_value=None),
    }


def test_login_zonder_opgeslagen_gegevens(mocker: Any) -> None:
    """Test dat login om gebruikersnaam en wachtwoord vraagt als niets is opgeslagen."""
    mocker.patch("flex2rijk.cli.keychain_get", return_value=None)
    mock_input = mocker.patch("builtins.input", return_value="  gebruiker  ")
    mocks = _patch_login(mocker, None)

    cli.login(otp="123456")

    mock_input.assert_called_once_with("Gebruikersnaam: ")
    mocks["getpass"].assert_called_once()
    assert mocks["run_browser"].call_args.args[:4] == (True, "gebruiker", "getypt", "123456")


def test_login_wachtwoord_uit_keychain(mocker: Any) -> None:
    """Test dat een gevonden wachtwoord getpass niet aanroept."""
    secrets = {"username": "gebruiker", "password": "opgeslagen"}
    mocker.patch("flex2rijk.cli.keychain_get", side_effect=secrets.get)
    ica = Path("/tmp/x.ica")
    mocks = _patch_login(mocker, ica)

    cli.login(headless=False, otp="123456")

    mocks["getpass"].assert_not_called()
    args = mocks["run_browser"].call_args.args
    assert args[:4] == (False, "gebruiker", "opgeslagen", "123456")
    mocks["open_ica"].assert_called_once_with(ica)
    mocks["sleep"].assert_called_once_with(15)


def test_login_wachtwoord_via_getpass(mocker: Any) -> None:
    """Test dat een ontbrekend wachtwoord terugvalt op getpass."""
    secrets = {"username": "gebruiker", "password": None}
    mocker.patch("flex2rijk.cli.keychain_get", side_effect=secrets.get)
    mocks = _patch_login(mocker, Path("/tmp/x.ica"))

    cli.login()

    mocks["getpass"].assert_called_once()
    assert mocks["run_browser"].call_args.args[:4] == (True, "gebruiker", "getypt", None)


def test_login_geen_ica(mocker: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """Test dat zonder ICA bestand niets wordt geopend."""
    mocker.patch("flex2rijk.cli.keychain_get", return_value="x")
    mocks = _patch_login(mocker, None)

    cli.login()

    mocks["open_ica"].assert_not_called()
    mocks["sleep"].assert_not_called()
    assert "Geen ICA bestand gevonden" in capsys.readouterr().out


def test_macos_keychain_attributes_bestaat(mocker: Any) -> None:
    """Test dat de kenmerken worden gelezen zonder het geheim te lezen."""
    mock_run = mocker.patch("subprocess.run", return_value=_run_result(0, '"icmt"<blob>="x"'))

    assert cli._macos_keychain_attributes("password") == '"icmt"<blob>="x"'
    argv = mock_run.call_args.args[0]
    assert argv == [
        "/usr/bin/security",
        "find-generic-password",
        "-s",
        "flex2rijk",
        "-a",
        "password",
    ]
    assert "-w" not in argv
    assert "-g" not in argv


def test_macos_keychain_attributes_ontbreekt(mocker: Any) -> None:
    """Test dat een ontbrekend item None geeft."""
    mocker.patch("subprocess.run", return_value=_run_result(44))
    assert cli._macos_keychain_attributes("password") is None


def test_read_password_toont_melding_op_macos(
    mocker: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test de melding over 'Sta toe' als macOS zo om toegang vraagt."""
    mocker.patch("platform.system", return_value="Darwin")
    mocker.patch(
        "flex2rijk.cli._macos_keychain_attributes",
        return_value='"icmt"<blob>="flex2rijk:confirm-access"',
    )
    mocker.patch("flex2rijk.cli.keychain_get", return_value="opgeslagen")

    assert cli._read_password() == "opgeslagen"
    out = capsys.readouterr().out
    assert "Kies 'Sta toe'" in out
    assert "'Sta altijd toe'" in out


@pytest.mark.parametrize("system", ["Darwin", "Linux"])
def test_read_password_zonder_melding(
    mocker: Any, capsys: pytest.CaptureFixture[str], system: str
) -> None:
    """Test dat de melding ontbreekt zonder opgeslagen wachtwoord of buiten macOS."""
    mocker.patch("platform.system", return_value=system)
    mock_attributes = mocker.patch("flex2rijk.cli._macos_keychain_attributes", return_value=None)
    mocker.patch("flex2rijk.cli.keychain_get", return_value=None)
    mocker.patch("getpass.getpass", return_value="getypt")

    assert cli._read_password() == "getypt"
    assert "Sta toe" not in capsys.readouterr().out
    assert mock_attributes.called is (system == "Darwin")


@pytest.mark.parametrize(("migrated", "expected"), [("oud", "oud"), (None, "getypt")])
def test_read_password_migreert_oud_item(mocker: Any, migrated: str | None, expected: str) -> None:
    """Test dat een item zonder markering wordt gemigreerd, met getpass als terugval."""
    mocker.patch("platform.system", return_value="Darwin")
    mocker.patch("flex2rijk.cli._macos_keychain_attributes", return_value='"acct"<blob>="x"')
    mock_migrate = mocker.patch("flex2rijk.cli._migrate_macos_password", return_value=migrated)
    mock_get = mocker.patch("flex2rijk.cli.keychain_get")
    mocker.patch("getpass.getpass", return_value="getypt")

    assert cli._read_password() == expected
    mock_migrate.assert_called_once()
    mock_get.assert_not_called()


def test_migrate_macos_password(mocker: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """Test dat het oude wachtwoord opnieuw wordt opgeslagen met confirm_access."""
    mocker.patch("flex2rijk.cli._macos_keychain_get", return_value="oud")
    mock_set = mocker.patch("flex2rijk.cli.keychain_set")

    assert cli._migrate_macos_password() == "oud"
    mock_set.assert_called_once_with("password", "oud", confirm_access=True)
    assert "Wachtwoord beveiligd" in capsys.readouterr().out


def test_migrate_macos_password_onleesbaar(mocker: Any) -> None:
    """Test dat een onleesbaar wachtwoord niet opnieuw wordt opgeslagen."""
    mocker.patch("flex2rijk.cli._macos_keychain_get", return_value=None)
    mock_set = mocker.patch("flex2rijk.cli.keychain_set")

    assert cli._migrate_macos_password() is None
    mock_set.assert_not_called()


# ── Browser ───────────────────────────────────────────────────────────────────


def test_run_browser(mocker: Any, tmp_path: Path) -> None:
    """Test het starten van de browser en doorgeven van de ICA."""
    mocker.patch("flex2rijk.cli._ensure_playwright_browsers")
    mock_pw = mocker.patch("playwright.sync_api.sync_playwright")
    p = mock_pw.return_value.__enter__.return_value
    browser = p.chromium.launch.return_value
    page = browser.new_context.return_value.new_page.return_value
    mock_login = mocker.patch("flex2rijk.cli._perform_page_login")
    mock_wait = mocker.patch("flex2rijk.cli._wait_for_ica", return_value=tmp_path / "a.ica")

    result = cli._run_browser(False, "u", "p", "123", tmp_path)

    p.chromium.launch.assert_called_once_with(headless=False)
    mock_login.assert_called_once_with(page, "u", "p", "123")
    mock_wait.assert_called_once_with(page, tmp_path)
    browser.close.assert_called_once()
    assert result == tmp_path / "a.ica"


def test_ensure_playwright_browsers_aanwezig(mocker: Any) -> None:
    """Test dat een werkende browser niet opnieuw wordt geinstalleerd."""
    mocker.patch("playwright.sync_api.sync_playwright")
    mock_run = mocker.patch("subprocess.run")
    cli._ensure_playwright_browsers()
    mock_run.assert_not_called()


def test_ensure_playwright_browsers_installeert(mocker: Any) -> None:
    """Test dat een ontbrekende browser wordt geinstalleerd."""
    mocker.patch("playwright.sync_api.sync_playwright", side_effect=RuntimeError("geen browser"))
    mock_run = mocker.patch("subprocess.run")
    cli._ensure_playwright_browsers()
    mock_run.assert_called_once_with(
        [sys.executable, "-m", "playwright", "install", "chromium"], check=True
    )


def test_perform_page_login_met_otp(mocker: Any) -> None:
    """Test het invullen van het loginformulier met meegegeven token."""
    mock_input = mocker.patch("builtins.input")
    page = mocker.MagicMock()

    cli._perform_page_login(page, "u", "p", "123456")

    mock_input.assert_not_called()
    page.goto.assert_called_once_with(cli.LOGIN_URL, wait_until="domcontentloaded", timeout=60000)
    page.get_by_role.return_value.fill.assert_has_calls(
        [mocker.call("u"), mocker.call("p"), mocker.call("123456")]
    )
    page.get_by_role.return_value.click.assert_called_once()


def test_perform_page_login_vraagt_otp(mocker: Any) -> None:
    """Test dat een ontbrekend token interactief wordt opgevraagd."""
    mocker.patch("builtins.input", return_value=" 654321 ")
    page = mocker.MagicMock()

    cli._perform_page_login(page, "u", "p", None)

    page.get_by_role.return_value.fill.assert_called_with("654321")


# ── ICA wachten ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "suggested", ["sessie.ica", "", "../../buiten.ica", "/tmp/elders.ica", "start.command"]
)
def test_wait_for_ica_negeert_bestandsnaam_van_server(
    mocker: Any, tmp_path: Path, suggested: str
) -> None:
    """Test dat de ICA altijd als session.ica in de downloadmap komt."""
    mocker.patch("flex2rijk.cli._handle_detect_button")
    mocker.patch("flex2rijk.cli._handle_install_button")
    page = mocker.MagicMock()
    download = page.expect_download.return_value.__enter__.return_value.value
    download.suggested_filename = suggested

    result = cli._wait_for_ica(page, tmp_path)

    assert result == tmp_path / "session.ica"
    download.save_as.assert_called_once_with(str(tmp_path / "session.ica"))


def test_wait_for_ica_timeout(mocker: Any, tmp_path: Path) -> None:
    """Test dat de screenshot naar het pad van mkstemp gaat en de fd sluit."""
    mocker.patch("flex2rijk.cli._handle_detect_button")
    mocker.patch("flex2rijk.cli._handle_install_button")
    shot = str(tmp_path / "flex2rijk_ica_timeout_abc.png")
    mock_mkstemp = mocker.patch("tempfile.mkstemp", return_value=(42, shot))
    mock_close = mocker.patch("os.close")
    page = mocker.MagicMock()
    page.expect_download.side_effect = PWTimeout("te traag")

    result = cli._wait_for_ica(page, tmp_path)

    assert result is None
    mock_mkstemp.assert_called_once_with(prefix="flex2rijk_ica_timeout_", suffix=".png")
    mock_close.assert_called_once_with(42)
    page.screenshot.assert_called_once_with(path=shot)


def test_handle_detect_button_klikt(mocker: Any) -> None:
    """Test klikken op de detectieknop."""
    page = mocker.MagicMock()
    cli._handle_detect_button(page)
    page.get_by_role.return_value.click.assert_called_once()


def test_handle_detect_button_afwezig(mocker: Any) -> None:
    """Test dat een ontbrekende detectieknop wordt genegeerd."""
    page = mocker.MagicMock()
    page.get_by_role.return_value.wait_for.side_effect = RuntimeError("weg")
    cli._handle_detect_button(page)
    page.get_by_role.return_value.click.assert_not_called()


def test_handle_install_button(mocker: Any) -> None:
    """Test klikken op 'Already installed'."""
    page = mocker.MagicMock()
    cli._handle_install_button(page)
    page.get_by_role.assert_called_once_with("link", name="Already installed")
    page.get_by_role.return_value.click.assert_called_once()


# ── main ──────────────────────────────────────────────────────────────────────


def test_main_login(mocker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test dat token en --no-headless naar login gaan."""
    monkeypatch.setattr(sys, "argv", ["flex2rijk", "123456", "--no-headless"])
    mock_login = mocker.patch("flex2rijk.cli.login")
    mock_setup = mocker.patch("flex2rijk.cli.setup")

    cli.main()

    mock_login.assert_called_once_with(headless=False, otp="123456")
    mock_setup.assert_not_called()


def test_main_login_standaard(mocker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test login met standaardopties."""
    monkeypatch.setattr(sys, "argv", ["flex2rijk"])
    mock_login = mocker.patch("flex2rijk.cli.login")

    cli.main()

    mock_login.assert_called_once_with(headless=True, otp=None)


def test_main_setup(mocker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test dat --setup het wachtwoord opslaat."""
    monkeypatch.setattr(sys, "argv", ["flex2rijk", "--setup"])
    mock_setup = mocker.patch("flex2rijk.cli.setup")
    mock_login = mocker.patch("flex2rijk.cli.login")

    cli.main()

    mock_setup.assert_called_once_with(store=True)
    mock_login.assert_not_called()


def test_main_setup_no_store(mocker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test dat --setup --no-store niets opslaat."""
    monkeypatch.setattr(sys, "argv", ["flex2rijk", "--setup", "--no-store"])
    mock_setup = mocker.patch("flex2rijk.cli.setup")

    cli.main()

    mock_setup.assert_called_once_with(store=False)


def test_main_no_store_zonder_setup(mocker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test dat --no-store zonder --setup een argparse-fout geeft."""
    monkeypatch.setattr(sys, "argv", ["flex2rijk", "--no-store"])
    mock_setup = mocker.patch("flex2rijk.cli.setup")
    mock_login = mocker.patch("flex2rijk.cli.login")

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2
    mock_setup.assert_not_called()
    mock_login.assert_not_called()


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_main_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test dat het draaien als module main() aanroept."""
    monkeypatch.setattr(sys, "argv", ["flex2rijk", "--help"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("flex2rijk.cli", run_name="__main__")
    assert exc.value.code == 0

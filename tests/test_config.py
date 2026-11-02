import sys
from pathlib import Path

import pytest

from dnskit.core.config import (
    CONFIG_TEMPLATE,
    ConfigError,
    config_path,
    load_config,
    parse_config,
    write_template,
)
from dnskit.core.propagation import GLOBAL_REGION

PATH = Path("config.toml")


def parse(text: str):
    return parse_config(text, PATH)


def test_a_missing_file_is_an_empty_config(tmp_path: Path) -> None:
    config = load_config(tmp_path / "nope.toml")

    assert not config.exists
    assert config.settings == {}
    assert config.compare_resolvers is None and config.propagation_resolvers is None
    assert config.for_command("lookup") == {}


def test_the_template_sets_nothing_until_uncommented() -> None:
    config = parse(CONFIG_TEMPLATE)

    assert config.exists
    assert config.settings == {}


def test_defaults_apply_to_commands_that_have_the_setting() -> None:
    config = parse('[defaults]\nserver = "1.1.1.1"\njson = true\n[lookup]\ntype = "MX"\n')

    assert config.for_command("lookup") == {"server": "1.1.1.1", "json": True, "type": "MX"}
    assert config.for_command("dnssec") == {"server": "1.1.1.1", "json": True}
    assert config.for_command("doctor") == {"json": True}  # doctor has no --server


def test_a_commands_own_section_wins_over_defaults() -> None:
    config = parse('[defaults]\nserver = "1.1.1.1"\n[lookup]\nserver = "9.9.9.9"\n')

    assert config.for_command("lookup")["server"] == "9.9.9.9"
    assert config.for_command("reverse")["server"] == "1.1.1.1"


def test_whole_numbers_are_fine_for_timeouts() -> None:
    assert parse("[lookup]\ntimeout = 2\n").for_command("lookup") == {"timeout": 2}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[lookups]\n", "[lookups] isn't a dnskit section"),
        ("lookup = 1\n", "lookup must be a section"),
        ("[lookup]\ncolour = 1\n", "[lookup] colour isn't a setting (use type, server, timeout"),
        ("[doctor]\nserver = '1.1.1.1'\n", "[doctor] server isn't a setting"),
        ("[defaults]\ncolour = 1\n", "[defaults] colour isn't a setting any command has"),
        ("[lookup]\ntimeout = 'fast'\n", "[lookup] timeout must be a number above 0, not 'fast'"),
        ("[lookup]\ntimeout = -1\n", "must be a number above 0, not -1"),
        ("[lookup]\ntimeout = true\n", "must be a number above 0, not True"),
        ("[reach]\nport = 4.5\n", "[reach] port must be a whole number above 0"),
        ("[doctor]\nquick = 'yes'\n", "[doctor] quick must be a true or false"),
        ("[email]\nselectors = 's1'\n", "[email] selectors must be a list of text"),
        ("[lookup\n", "isn't valid TOML"),
    ],
)
def test_mistakes_name_the_setting(text: str, message: str) -> None:
    with pytest.raises(ConfigError) as error:
        parse(text)

    assert str(error.value).startswith(str(PATH))
    assert message in str(error.value)


def test_compare_resolvers() -> None:
    config = parse(
        "[compare]\nresolvers = [\n"
        '  { name = "Google", address = "8.8.8.8" },\n'
        '  { name = "Office", address = "2001:db8::53" },\n]\n'
    )

    assert config.compare_resolvers == (("Google", "8.8.8.8"), ("Office", "2001:db8::53"))
    assert config.settings == {}  # resolvers aren't an option default


def test_propagation_resolvers_with_regions() -> None:
    config = parse(
        "[propagation]\ntimeout = 2.0\nresolvers = [\n"
        '  { name = "Google", address = "8.8.8.8", region = "global" },\n'
        '  { name = "Telkom", address = "196.43.1.14", location = "South Africa", '
        'region = "Africa" },\n'
        '  { name = "Mine", address = "192.0.2.53" },\n]\n'
    )

    google, telkom, mine = config.propagation_resolvers
    assert (google.region, google.location, google.anycast) == (GLOBAL_REGION, "nearest site", True)
    assert (telkom.location, telkom.region, telkom.anycast) == ("South Africa", "Africa", False)
    assert (mine.location, mine.region) == ("unknown", "Other")
    assert config.for_command("propagation") == {"timeout": 2.0}


@pytest.mark.parametrize(
    ("resolvers", "message"),
    [
        ("[]", "must be a list of resolvers"),
        ('["8.8.8.8"]', "entry 1 must be a table"),
        ('[{ name = "Google" }]', "entry 1 needs a address"),
        ('[{ address = "8.8.8.8" }]', "entry 1 needs a name"),
        ('[{ name = "G", address = "dns.google" }]', "address that isn't an IP: 'dns.google'"),
        ('[{ name = "G", address = "8.8.8.8", port = "53" }]', "unknown field 'port'"),
        ('[{ name = "", address = "8.8.8.8" }]', "entry 1 name must be text"),
        (
            '[{ name = "A", address = "8.8.8.8" }, { name = "B", address = "8.8.8.8" }]',
            "lists the same address twice",
        ),
    ],
)
def test_bad_resolver_lists(resolvers: str, message: str) -> None:
    with pytest.raises(ConfigError) as error:
        parse(f"[compare]\nresolvers = {resolvers}\n")

    assert "[compare] resolvers" in str(error.value)
    assert message in str(error.value)


def test_config_path_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DNSKIT_CONFIG", str(tmp_path / "mine.toml"))

    assert config_path() == tmp_path / "mine.toml"


def test_config_path_on_windows(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("DNSKIT_CONFIG")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(tmp_path))

    assert config_path() == tmp_path / "dnskit" / "config.toml"


def test_config_path_elsewhere(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("DNSKIT_CONFIG")
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    assert config_path() == tmp_path / "dnskit" / "config.toml"


def test_write_template_creates_folders_but_never_overwrites(tmp_path: Path) -> None:
    path = tmp_path / "new" / "config.toml"

    assert write_template(path) == path
    assert path.read_text(encoding="utf-8") == CONFIG_TEMPLATE
    with pytest.raises(ConfigError, match="already exists"):
        write_template(path)


def test_load_config_reads_the_file(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("[doctor]\nquick = true\n", encoding="utf-8")

    config = load_config(path)

    assert config.exists and config.path == path
    assert config.for_command("doctor") == {"quick": True}


def test_an_unreadable_config_names_the_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Can't read"):
        load_config(tmp_path)  # a folder, not a file


def test_a_config_that_cant_be_written(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("", encoding="utf-8")

    with pytest.raises(ConfigError, match="Can't write"):
        write_template(blocker / "config.toml")

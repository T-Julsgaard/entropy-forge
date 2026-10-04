"""Reject invalid random-output arguments before starting any harvesting."""
import pytest

from entropy_forge import cli


@pytest.mark.parametrize("argv, message", [
    (["--bytes", "0"], "must be a positive integer"),
    (["--bytes", "-1"], "must be a positive integer"),
    (["--max-rounds", "0"], "must be a positive integer"),
    (["--max-rounds", "-1"], "must be a positive integer"),
    (["--format", "uuid", "--bytes", "1"], "UUID output requires at least 16 bytes"),
    (["--format", "uuid", "--bytes", "8"], "UUID output requires at least 16 bytes"),
    (["--format", "uuid", "--bytes", "15"], "UUID output requires at least 16 bytes"),
])
def test_invalid_random_arguments_do_not_harvest(monkeypatch, capsys, argv, message):
    def unexpected_harvest(args):
        pytest.fail("invalid arguments must be rejected before harvesting")

    monkeypatch.setattr(cli, "cmd_random", unexpected_harvest)
    with pytest.raises(SystemExit) as exc:
        cli.main(["random", *argv])
    assert exc.value.code == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize("argv", [
    ["--bytes", "1"],
    ["--format", "uuid", "--bytes", "16"],
    ["--format", "uuid"],
    ["--format", "uuid", "--bytes", "1", "--base64"],
])
def test_valid_random_arguments_reach_command(monkeypatch, argv):
    received = []

    def capture(args):
        received.append(args)
        return 0

    monkeypatch.setattr(cli, "cmd_random", capture)
    assert cli.main(["random", *argv]) == 0
    assert len(received) == 1

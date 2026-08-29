from scripts.live_vm_demo import (
    DEFAULT_MACHINE,
    DEFAULT_PROJECT,
    DEFAULT_ZONE,
    PROOF_MARKER,
    gcloud_command,
    main,
)


def test_preflight_never_calls_provider(capsys):
    assert main([]) == 0
    output = capsys.readouterr().out
    assert "PREFLIGHT ONLY" in output
    assert DEFAULT_PROJECT in output


def test_execute_requires_exact_project_confirmation(capsys):
    assert main(["--execute", "--confirm-project", "wrong-project"]) == 2
    assert "must exactly match" in capsys.readouterr().err


def test_gcloud_launch_has_provider_enforced_delete_deadline():
    command = gcloud_command(DEFAULT_PROJECT, DEFAULT_ZONE, "warden-test", DEFAULT_MACHINE, 5)
    joined = " ".join(command)
    assert "--provisioning-model SPOT" in joined
    assert "--instance-termination-action DELETE" in joined
    assert "--max-run-duration 300s" in joined
    assert "--no-address" in joined
    assert PROOF_MARKER in joined

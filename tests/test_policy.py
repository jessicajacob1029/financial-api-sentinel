"""Unit tests for proxy/policy.py (Phase 7C.5).

Acceptance (doc SS7C.5): a malformed policy file causes a startup
failure, not a silent default -- every malformed-input test here asserts
PolicyError is raised, never that load_policy() quietly substitutes
something safe-looking.
"""

import pytest

from proxy.policy import PolicyError, load_policy

VALID_YAML = """
risk_threshold: 2
challenge_threshold: 1
soft_signal_weights:
  ip_delta: 1
  ja4h_delta: 2
"""


def _write(tmp_path, content: str):
    p = tmp_path / "policy.yaml"
    p.write_text(content)
    return p


def test_shipped_policy_yaml_is_itself_valid():
    """The real, committed policy.yaml (loaded once at import time into
    the POLICY singleton) must pass its own validation."""
    from proxy.policy import POLICY

    assert POLICY.risk_threshold == 2
    assert POLICY.challenge_threshold == 1
    assert POLICY.soft_signal_weights == {"ip_delta": 1, "ja4h_delta": 2}


def test_valid_policy_file_loads(tmp_path):
    path = _write(tmp_path, VALID_YAML)

    policy = load_policy(path)

    assert policy.risk_threshold == 2
    assert policy.challenge_threshold == 1
    assert policy.soft_signal_weights == {"ip_delta": 1, "ja4h_delta": 2}


def test_missing_file_raises():
    with pytest.raises(PolicyError, match="can't read"):
        load_policy("/nonexistent/path/policy.yaml")


def test_invalid_yaml_raises(tmp_path):
    path = _write(tmp_path, "risk_threshold: [this is not: valid yaml structure for a mapping")

    with pytest.raises(PolicyError):
        load_policy(path)


def test_non_mapping_top_level_raises(tmp_path):
    path = _write(tmp_path, "- just\n- a\n- list\n")

    with pytest.raises(PolicyError, match="mapping"):
        load_policy(path)


def test_unknown_top_level_key_raises(tmp_path):
    path = _write(tmp_path, VALID_YAML + "\nextra_key: 123\n")

    with pytest.raises(PolicyError, match="unknown top-level key"):
        load_policy(path)


def test_missing_top_level_key_raises(tmp_path):
    path = _write(tmp_path, "risk_threshold: 2\nchallenge_threshold: 1\n")  # no soft_signal_weights

    with pytest.raises(PolicyError, match="missing required top-level key"):
        load_policy(path)


def test_challenge_threshold_not_below_risk_threshold_raises(tmp_path):
    path = _write(
        tmp_path,
        "risk_threshold: 2\nchallenge_threshold: 2\nsoft_signal_weights:\n  ip_delta: 1\n  ja4h_delta: 2\n",
    )

    with pytest.raises(PolicyError, match="strictly less than"):
        load_policy(path)


def test_negative_risk_threshold_raises(tmp_path):
    path = _write(
        tmp_path,
        "risk_threshold: -1\nchallenge_threshold: 0\nsoft_signal_weights:\n  ip_delta: 1\n  ja4h_delta: 2\n",
    )

    with pytest.raises(PolicyError, match="positive integer"):
        load_policy(path)


def test_non_integer_weight_raises(tmp_path):
    path = _write(
        tmp_path,
        "risk_threshold: 2\nchallenge_threshold: 1\nsoft_signal_weights:\n  ip_delta: not-a-number\n  ja4h_delta: 2\n",
    )

    with pytest.raises(PolicyError, match="ip_delta"):
        load_policy(path)


def test_unknown_weight_key_raises(tmp_path):
    path = _write(
        tmp_path,
        "risk_threshold: 2\nchallenge_threshold: 1\n"
        "soft_signal_weights:\n  ip_delta: 1\n  ja4h_delta: 2\n  typo_field: 5\n",
    )

    with pytest.raises(PolicyError, match="unknown key"):
        load_policy(path)


def test_missing_weight_key_raises(tmp_path):
    path = _write(
        tmp_path,
        "risk_threshold: 2\nchallenge_threshold: 1\nsoft_signal_weights:\n  ip_delta: 1\n",
    )

    with pytest.raises(PolicyError, match="missing required key"):
        load_policy(path)


def test_boolean_is_not_accepted_as_integer(tmp_path):
    # Python's bool is a subclass of int -- `True == 1` -- easy to
    # accidentally accept; this must be rejected explicitly.
    path = _write(
        tmp_path,
        "risk_threshold: true\nchallenge_threshold: 1\nsoft_signal_weights:\n  ip_delta: 1\n  ja4h_delta: 2\n",
    )

    with pytest.raises(PolicyError, match="positive integer"):
        load_policy(path)

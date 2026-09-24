"""Config-driven decision policy (Phase 7C.5).

Loads and strictly validates policy.yaml once, at import time (i.e. at
addon startup) -- a malformed file raises PolicyError immediately and
loudly, never falls back to a hardcoded default silently. This is the one
other place (besides 7C.1's revocation) this phase is pre-approved to
touch engine.py: it's the source of the threshold/weight values engine.py
and addon.py now read, replacing the constants that used to live directly
in config.py.

Hard signals themselves are NOT policy-configurable, deliberately -- see
policy.yaml's own header comment for why.
"""

import pathlib
from dataclasses import dataclass

import yaml

from config import REPO_ROOT

POLICY_PATH = REPO_ROOT / "policy.yaml"

_REQUIRED_TOP_LEVEL_KEYS = {"risk_threshold", "challenge_threshold", "soft_signal_weights"}
_REQUIRED_WEIGHT_KEYS = {"ip_delta", "ja4h_delta"}


class PolicyError(Exception):
    """Raised on any malformed policy.yaml -- never caught to silently
    fall back to defaults; letting this propagate is the point."""


@dataclass(frozen=True)
class Policy:
    risk_threshold: int
    challenge_threshold: int
    soft_signal_weights: dict[str, int]


def load_policy(path=POLICY_PATH) -> Policy:
    path = pathlib.Path(path)
    try:
        raw_text = path.read_text()
    except OSError as exc:
        raise PolicyError(f"can't read policy file at {path}: {exc}") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy file at {path} is not valid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyError(f"policy file at {path} must be a YAML mapping at the top level, got {type(data).__name__}")

    unknown_top = set(data.keys()) - _REQUIRED_TOP_LEVEL_KEYS
    missing_top = _REQUIRED_TOP_LEVEL_KEYS - set(data.keys())
    if unknown_top:
        raise PolicyError(f"policy file has unknown top-level key(s): {sorted(unknown_top)}")
    if missing_top:
        raise PolicyError(f"policy file is missing required top-level key(s): {sorted(missing_top)}")

    risk_threshold = data["risk_threshold"]
    challenge_threshold = data["challenge_threshold"]
    weights = data["soft_signal_weights"]

    if not isinstance(risk_threshold, int) or isinstance(risk_threshold, bool) or risk_threshold < 1:
        raise PolicyError(f"risk_threshold must be a positive integer, got {risk_threshold!r}")
    if not isinstance(challenge_threshold, int) or isinstance(challenge_threshold, bool) or challenge_threshold < 0:
        raise PolicyError(f"challenge_threshold must be a non-negative integer, got {challenge_threshold!r}")
    if challenge_threshold >= risk_threshold:
        raise PolicyError(
            f"challenge_threshold ({challenge_threshold}) must be strictly less than "
            f"risk_threshold ({risk_threshold}), or the step-up band is empty"
        )

    if not isinstance(weights, dict):
        raise PolicyError(f"soft_signal_weights must be a mapping, got {type(weights).__name__}")
    unknown_weights = set(weights.keys()) - _REQUIRED_WEIGHT_KEYS
    missing_weights = _REQUIRED_WEIGHT_KEYS - set(weights.keys())
    if unknown_weights:
        raise PolicyError(f"soft_signal_weights has unknown key(s): {sorted(unknown_weights)}")
    if missing_weights:
        raise PolicyError(f"soft_signal_weights is missing required key(s): {sorted(missing_weights)}")
    for key, value in weights.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise PolicyError(f"soft_signal_weights.{key} must be a non-negative integer, got {value!r}")

    return Policy(
        risk_threshold=risk_threshold,
        challenge_threshold=challenge_threshold,
        soft_signal_weights=dict(weights),
    )


# Loaded once at import time -- every caller shares this one validated
# instance. A malformed policy.yaml raises PolicyError here, which
# propagates out of the very first `import proxy.policy` (or anything
# that imports it, e.g. proxy.engine), failing addon startup loudly.
POLICY = load_policy()

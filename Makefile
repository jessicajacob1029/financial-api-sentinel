.PHONY: setup setup-mtls audit clean test backend proxy attack-a attack-b attack-c attack-d attack-e attack-f

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
MITMDUMP := $(VENV)/bin/mitmdump
# mitmproxy requires Python >= 3.10; the system default python3 on this
# machine is 3.9, so setup pins to python3.10 explicitly (found via
# Homebrew at /opt/homebrew/bin/python3.10). Override with `make setup PY=...`
# if your system python3 is already >= 3.10.
PY := python3.10

# Phase 7A.1: mTLS on the proxy<->backend leg is opt-in. `make backend
# MTLS=1` / `make proxy MTLS=1` / `make attack-a MTLS=1` (etc.) enable it;
# plain `make backend` / `make proxy` stay on the original plaintext leg.
# MTLS_ENV is the env-var form config.py reads, derived once here so
# every recipe below stays in agreement about which mode it's in.
MTLS ?= 0
ifeq ($(MTLS),1)
MTLS_ENV := MTLS_BACKEND_ENABLED=true
else
MTLS_ENV := MTLS_BACKEND_ENABLED=false
endif

setup:
	$(PY) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PYTHON) scripts/generate_ca.py

# Requires `make setup` to have run first (needs the venv and the CA).
# Not chained as a prerequisite on purpose -- `setup` is .PHONY, so
# chaining it here would re-run the full venv/dependency install every
# time, even when nothing changed.
setup-mtls:
	$(PYTHON) scripts/generate_mtls_certs.py

audit:
	$(PIP) install pip-audit
	$(VENV)/bin/pip-audit -r requirements.txt

test:
	PYTHONPATH=. $(PYTHON) -m pytest tests/ -v

# Run these in separate terminals: backend first, then proxy, then attacks.
# Add MTLS=1 to every terminal's command consistently, or leave it off
# everywhere -- mixing modes across terminals will break the demo (see
# README).
backend:
ifeq ($(MTLS),1)
	PYTHONPATH=. $(MTLS_ENV) $(VENV)/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000 \
		--ssl-certfile certs/backend-server.pem --ssl-keyfile certs/backend-server.key \
		--ssl-ca-certs certs/ca.pem --ssl-cert-reqs 2
else
	PYTHONPATH=. $(MTLS_ENV) $(VENV)/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000
endif

proxy:
ifeq ($(MTLS),1)
	PYTHONPATH=. $(MTLS_ENV) $(MITMDUMP) -q --mode reverse:https://127.0.0.1:8000 --listen-port 8080 \
		--set confdir=./certs --set client_certs=certs/proxy-client.pem \
		--set ssl_verify_upstream_trusted_ca=certs/ca.pem -s proxy/addon.py
else
	PYTHONPATH=. $(MTLS_ENV) $(MITMDUMP) -q --mode reverse:http://127.0.0.1:8000 --listen-port 8080 --set confdir=./certs -s proxy/addon.py
endif

attack-a:
	PYTHONPATH=. $(MTLS_ENV) $(PYTHON) client/script_a_legit.py

attack-b:
	PYTHONPATH=. $(MTLS_ENV) $(PYTHON) client/script_b_thief.py

attack-c:
	PYTHONPATH=. $(MTLS_ENV) $(PYTHON) client/script_c_hijack.py

# Scenario 2 (untrusted client cert rejected server-side) only runs when
# MTLS=1 and the backend/proxy are already up in that mode; scenario 1
# (untrusted server CA) works either way.
attack-d:
	PYTHONPATH=. $(MTLS_ENV) $(PYTHON) client/script_d_untrusted.py

# 7C.1: revoke a legitimate, currently-passing session's token mid-demo
# and show the very next request instantly blocked. Run attack-a first.
attack-e:
	PYTHONPATH=. $(MTLS_ENV) $(PYTHON) client/script_e_revoke_demo.py

# 7C.2: step-up challenge -- needs the same loopback alias as attack-a's
# IP-roam step (see script_f_stepup_demo.py's docstring). Run attack-a first.
attack-f:
	PYTHONPATH=. $(MTLS_ENV) $(PYTHON) client/script_f_stepup_demo.py

clean:
	rm -rf $(VENV) certs/ca.key certs/ca.pem certs/mitmproxy-ca.pem certs/backend-server.key certs/backend-server.pem certs/proxy-client.pem demo_state

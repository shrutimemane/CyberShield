"""
CyberShield - registration & firewall validation tests
======================================================

Run from the CyberShield folder:
    ..\\venv\\Scripts\\python -m pytest tests/ -q

Covers:
* Registration happy path + every rejection rule (frontend is mirrored in
  static/js/validators.js; the server is the source of truth).
* Strict firewall target validation table from the project spec.
* First-match-wins simulator behavior preserved after validation changes.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from backend.app import app  # initializes DB + seeds
from backend.database import reset_db
from backend.models import db, User, FirewallRule
from backend.utils.validators import (ValidationError, validate_firewall_target,
                                      validate_registration,
                                      validate_simulate_payload)


@pytest.fixture()
def client():
    with app.app_context():
        reset_db(app)
    with app.test_client() as c:
        yield c


# --------------------------------------------------------------------- #
# validate_registration (unit)
# --------------------------------------------------------------------- #
def _reg(**over):
    base = dict(full_name="Test User", username="tester", email="t@example.com",
                password="secret123", confirm_password="secret123")
    base.update(over)
    return base


def test_registration_accepts_valid_fields():
    fields = validate_registration(**_reg())
    assert fields["username"] == "tester"
    assert fields["email"] == "t@example.com"


@pytest.mark.parametrize("over", [
    {"full_name": "A"},                        # too short
    {"username": "ab"},                        # too short
    {"username": "bad name!"},                 # invalid chars
    {"email": "not-an-email"},                 # no @
    {"email": "a@b"},                          # no TLD
    {"password": "short1"},                    # < 8 chars
    {"password": "nodigitshere"},              # letters only
    {"confirm_password": "different123"},       # mismatch
])
def test_registration_rejects_bad_input(over):
    with pytest.raises(ValidationError):
        validate_registration(**_reg(**over))


# --------------------------------------------------------------------- #
# /register route (HTTP)
# --------------------------------------------------------------------- #
def test_register_creates_hashed_user_and_redirects(client):
    resp = client.post("/register", data=_reg(), follow_redirects=False)
    assert resp.status_code == 302
    with app.app_context():
        u = User.query.filter_by(username="tester").first()
        assert u is not None
        assert u.email == "t@example.com"
        assert u.password_hash != "secret123"
        assert u.password_hash.startswith(("pbkdf2:", "scrypt:"))
        assert "secret123" not in u.password_hash


def test_register_rejects_duplicate_username(client):
    client.post("/register", data=_reg(), follow_redirects=False)
    resp = client.post("/register", data=_reg(email="other@example.com"))
    assert resp.status_code == 400
    assert b"already taken" in resp.data


def test_register_rejects_duplicate_email(client):
    client.post("/register", data=_reg(), follow_redirects=False)
    resp = client.post("/register", data=_reg(username="otheruser"))
    assert resp.status_code == 400
    assert b"email already exists" in resp.data


def test_register_rejects_invalid_email_and_mismatch(client):
    resp = client.post("/register", data=_reg(email="broken"))
    assert resp.status_code == 400
    resp = client.post("/register", data=_reg(confirm_password="different123"))
    assert resp.status_code == 400


def test_new_user_can_login_and_reach_dashboard(client):
    client.post("/register", data=_reg(), follow_redirects=False)
    assert client.post("/login",
                       data={"username": "tester", "password": "secret123"}
                       ).status_code == 302
    assert client.get("/dashboard").status_code == 200


def test_wrong_password_rejected_and_pages_protected(client):
    client.post("/register", data=_reg(), follow_redirects=False)
    resp = client.post("/login",
                       data={"username": "tester", "password": "wrongpass1"})
    assert resp.status_code == 200          # re-renders login with error
    assert b"Invalid username or password" in resp.data
    assert client.get("/dashboard").status_code == 302   # redirected to login
    assert client.get("/api/dashboard").status_code == 401


# --------------------------------------------------------------------- #
# Firewall target validation (spec table)
# --------------------------------------------------------------------- #
@pytest.mark.parametrize("target", ["203.0.113.66", "203.0.113.66:80", "any"])
def test_firewall_target_accepts_supported(target):
    assert validate_firewall_target(target)


@pytest.mark.parametrize("target", [
    "999.1.1.1", "192.168.1", "192.168.1.1.5", "abc.def.ghi.jkl",
    "203.0.113.66:99999", "", "012.02.32.0444", "192.168.1.0/24",
    "203.0.113.66:0", "203.0.113.66:-80", "1.2.3.4:80:90", "  ",
])
def test_firewall_target_rejects_malformed(target):
    with pytest.raises(ValidationError):
        validate_firewall_target(target)


def test_firewall_api_rejects_bad_target_and_saves_nothing(client):
    client.post("/login", data={"username": "admin", "password": "admin123"})
    for bad in ("999.1.1.1", "abc.def.ghi.jkl", "192.168.1.0/24", ""):
        resp = client.post("/api/firewall/rules",
                           json={"target": bad, "rule_type": "BLOCK"})
        assert resp.status_code == 400, bad
    with app.app_context():
        assert FirewallRule.query.count() == 0


def test_firewall_api_accepts_valid_target_and_simulates(client):
    client.post("/login", data={"username": "admin", "password": "admin123"})
    resp = client.post("/api/firewall/rules",
                       json={"target": "203.0.113.66:80", "rule_type": "BLOCK",
                             "reason": "test"})
    assert resp.status_code == 200
    sim = client.post("/api/firewall/simulate",
                      json={"src_ip": "203.0.113.66", "dst_port": 80})
    assert sim.get_json()["action"] == "DENY"
    # first-match-wins: an earlier ALLOW for the same IP denies nothing
    client.post("/api/firewall/rules",
                json={"target": "203.0.113.66", "rule_type": "ALLOW"})
    sim2 = client.post("/api/firewall/simulate",
                       json={"src_ip": "203.0.113.66", "dst_port": 22}).get_json()
    assert sim2["action"] == "ALLOW"


def test_simulate_payload_validation():
    assert validate_simulate_payload("203.0.113.66", "80") == ("203.0.113.66", 80)
    assert validate_simulate_payload("any", None) == ("any", None)
    with pytest.raises(ValidationError):
        validate_simulate_payload("999.9.9.9", None)
    with pytest.raises(ValidationError):
        validate_simulate_payload("1.2.3.4", "70000")

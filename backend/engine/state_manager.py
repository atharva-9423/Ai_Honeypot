"""Session state manager — per-session isolation, in-memory authoritative state."""
from __future__ import annotations
import threading
import time
import secrets
from dataclasses import dataclass, field
from .virtual_fs import VirtualFS, default_fs


@dataclass
class SessionState:
    session_id: str
    cwd: str = "/home/sentinel"
    fs: VirtualFS = field(default_factory=default_fs)
    history: list[str] = field(default_factory=list)
    env: dict = field(default_factory=lambda: {
        "USER": "sentinel", "HOME": "/home/sentinel", "SHELL": "/bin/bash",
        "PATH": "/usr/local/bin:/usr/bin:/bin", "HOSTNAME": "server01"})
    created_at: float = field(default_factory=time.time)
    status: str = "active"
    deception_deployed: bool = False
    deception_actions: list[dict] = field(default_factory=list)
    event_count: int = 0
    prev_dir: str = "/home/sentinel"
    # Full transcript for terminal replay: [{command, output, cwd, clear, exit}].
    # Never re-executed — replay is display-only.
    transcript: list[dict] = field(default_factory=list)
    # Learning state: per-area access counts, expansions, decoy manifest.
    interests: dict = field(default_factory=dict)
    expansions: list[dict] = field(default_factory=list)
    decoy_manifest: dict = field(default_factory=dict)
    command_log: list[dict] = field(default_factory=list)


_lock = threading.Lock()
_sessions: dict[str, SessionState] = {}


def new_session_id() -> str:
    return "SES-" + secrets.token_hex(3).upper()


def create_session() -> SessionState:
    from ..company.fs_builder import build_session_fs
    with _lock:
        sid = new_session_id()
        while sid in _sessions:
            sid = new_session_id()
        fs, manifest = build_session_fs()
        st = SessionState(session_id=sid, fs=fs, decoy_manifest=manifest)
        _sessions[sid] = st
        return st


def get_session(sid: str) -> SessionState | None:
    with _lock:
        return _sessions.get(sid)


def list_sessions() -> list[SessionState]:
    with _lock:
        return list(_sessions.values())


def reset_session(sid: str) -> SessionState | None:
    from ..company.fs_builder import build_session_fs
    with _lock:
        st = _sessions.get(sid)
        if not st:
            return None
        st.fs, st.decoy_manifest = build_session_fs()
        st.cwd = "/home/sentinel"
        st.prev_dir = "/home/sentinel"
        st.history = []
        st.transcript = []
        st.interests = {}
        st.expansions = []
        st.command_log = []
        st.deception_deployed = False
        st.deception_actions = []
        st.event_count = 0
        st.status = "active"
        return st


def close_session(sid: str):
    with _lock:
        st = _sessions.get(sid)
        if st:
            st.status = "closed"


def reset_all_sessions() -> int:
    """Drop every in-memory session (filesystems, histories, learning state)."""
    with _lock:
        n = len(_sessions)
        _sessions.clear()
        return n

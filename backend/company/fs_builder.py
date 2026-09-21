"""Per-session filesystem builder: deterministic skeleton + generated contents.

Structure (dirs, system files) is always deterministic. Company file
CONTENTS come from the decoy generator — AI-produced when Groq is
configured, validated template fallback otherwise.
"""
from __future__ import annotations
from ..engine.virtual_fs import VirtualFS, default_fs
from .decoy_generator import generate_bundle


def build_session_fs() -> tuple[VirtualFS, dict]:
    fs = default_fs()
    bundle, manifest = generate_bundle()
    for path, content in bundle.items():
        if fs.is_file(path):
            fs.files[path]["content"] = content
    return fs, manifest

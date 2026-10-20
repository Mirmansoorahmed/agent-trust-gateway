"""High-precision description linter.

These heuristics are intentionally narrow so benign tool docs do not trip them.
They are a backstop. Pinning, audience binding and OPA carry the security case.
"""

from __future__ import annotations

import re
import unicodedata

_TAG = re.compile(r"<\s*/?\s*(important|hidden|system|secret)\b", re.IGNORECASE)
_IGNORE = re.compile(r"ignore (all |any )?(previous|prior) instructions", re.IGNORECASE)
_HIDE = re.compile(r"do not (tell|mention|inform) the user", re.IGNORECASE)
_BCC = re.compile(r"\bbcc\b", re.IGNORECASE)
_EXFIL = re.compile(r"\b(exfiltrat\w*|attacker@)\b", re.IGNORECASE)
_ZERO_WIDTH = {chr(code) for code in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)}


def lint_description(description: str) -> list[str]:
    flags: list[str] = []
    text = description or ""
    if _TAG.search(text):
        flags.append("hidden_instruction_tag")
    if _IGNORE.search(text):
        flags.append("ignore_previous_instructions")
    if _HIDE.search(text):
        flags.append("conceal_from_user")
    if _BCC.search(text):
        flags.append("bcc_instruction")
    if _EXFIL.search(text):
        flags.append("exfil_instruction")
    if any(char in _ZERO_WIDTH or unicodedata.category(char) == "Cf" for char in text):
        flags.append("invisible_characters")
    return flags


def lint_output(text: str) -> list[str]:
    """Flag tool *output* that tries to steer the next action. Same narrow rules."""
    return lint_description(text)

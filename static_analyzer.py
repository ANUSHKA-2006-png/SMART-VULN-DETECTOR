# backend/analyzer/static_analyzer.py
"""
Two-layer analyzer:
  Layer 1 — Pure Python regex/AST pattern scanner (always works, no external tools)
  Layer 2 — Slither (runs if available, adds deeper findings)
Results are merged and deduplicated.
"""
import re, subprocess, json, tempfile, os, shutil
from pathlib import Path

# ─── SWC metadata ────────────────────────────────────────────────────────────
SLITHER_TO_SWC = {
    "reentrancy-eth":          "SWC-107",
    "reentrancy-no-eth":       "SWC-107",
    "reentrancy-benign":       "SWC-107",
    "tx-origin":               "SWC-115",
    "suicidal":                "SWC-106",
    "arbitrary-send-eth":      "SWC-105",
    "unchecked-lowlevel":      "SWC-104",
    "unchecked-send":          "SWC-104",
    "weak-prng":               "SWC-120",
    "timestamp":               "SWC-116",
    "shadowing-state":         "SWC-119",
    "uninitialized-state":     "SWC-109",
    "controlled-delegatecall": "SWC-112",
    "locked-ether":            "SWC-132",
    "msg-value-loop":          "SWC-113",
    "integer-overflow":        "SWC-101",
}

FIX_MAP = {
    "reentrancy-eth":
        "Use Checks-Effects-Interactions: update state BEFORE external calls. "
        "Add OpenZeppelin ReentrancyGuard nonReentrant modifier.",
    "tx-origin":
        "Replace tx.origin with msg.sender. tx.origin is the original EOA "
        "and is vulnerable to phishing/relay attacks.",
    "arbitrary-send-eth":
        "Restrict ETH transfer targets. Add onlyOwner or role-based access control.",
    "unchecked-lowlevel":
        "Always check the bool returned by .call(). Use: (bool ok,) = addr.call{...}(); require(ok);",
    "weak-prng":
        "Never use block.timestamp/blockhash for randomness. Use Chainlink VRF.",
    "timestamp":
        "Avoid block.timestamp for critical decisions — miners can shift it ~900s.",
    "suicidal":
        "Remove selfdestruct or guard it with strict onlyOwner access control.",
    "controlled-delegatecall":
        "Never delegatecall to a user-controlled address — this allows full contract takeover.",
    "integer-overflow":
        "Use Solidity >=0.8.0 (built-in checked math) or OpenZeppelin SafeMath.",
    "shadowing-state":
        "Rename the local variable — it shadows a state variable with the same name.",
    "uninitialized-state":
        "Explicitly initialize all state variables before use.",
    "locked-ether":
        "Contract receives ETH but has no withdrawal function. Add a withdraw() method.",
}



def _get_pragma_version(source: str) -> tuple[int, int]:
    """Return (major, minor) from pragma, e.g. (0, 8) for ^0.8.0"""
    m = re.search(r'pragma solidity\s*[\^~>=<]*\s*(\d+)\.(\d+)', source)
    if m:
        return int(m.group(1)), int(m.group(2))
    return (0, 8)  # assume safe default


def _get_function_blocks(source: str) -> list[dict]:
    """Extract function name + body pairs for pattern matching."""
    funcs = []
    for m in re.finditer(
        r'function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?'
        r'[^{]*\{', source
    ):
        start = m.end() - 1
        depth = 0
        i = start
        while i < len(source):
            if source[i] == '{':
                depth += 1
            elif source[i] == '}':
                depth -= 1
                if depth == 0:
                    funcs.append({
                        "name":       m.group(1),
                        "visibility": m.group(2) or "public",
                        "body":       source[start:i+1],
                        "line":       source[:m.start()].count('\n') + 1,
                    })
                    break
            i += 1
    return funcs


def _check_missing_access_control(source: str) -> bool:
    """Flag public/external functions with sensitive names that lack access guards."""
    SENSITIVE = re.compile(
        r'\b(changeOwner|setOwner|transferOwnership|mint|burn|pause|unpause|'
        r'withdraw|upgrade|initialize|selfdestruct|kill|destroy)\b'
    )
    HAS_GUARD = re.compile(
        r'require\s*\(\s*msg\.sender\s*==|onlyOwner|onlyAdmin|onlyRole|'
        r'_checkOwner|hasRole|isOwner|modifier\s+only'
    )
    for func in _get_function_blocks(source):
        if func["visibility"] in ("public", "external"):
            if SENSITIVE.search(func["name"]) and not HAS_GUARD.search(func["body"]):
                return True
    return False


def _check_unchecked_call(source: str) -> bool:
    """Flag .call() whose return value is not captured or checked."""
    for m in re.finditer(r'([\w.]+)\.call\s*[\({]', source):
        # Get surrounding context (100 chars)
        ctx = source[max(0, m.start()-10):m.end()+120]
        # If the return bool is captured → (bool ...) = or bool ... =
        if re.search(r'\(bool\s+\w+', ctx) or re.search(r'bool\s+\w+\s*=', ctx):
            continue
        return True
    return False


def _check_integer_overflow(source: str) -> bool:
    """Flag arithmetic ops on Solidity <0.8 without SafeMath."""
    major, minor = _get_pragma_version(source)
    if major == 0 and minor >= 8:
        return False  # built-in checked math
    if 'SafeMath' in source:
        return False
    return bool(re.search(r'[\w\[\]]+\s*[\+\-\*]=\s*[\w\[\]]+', source))


def _check_selfdestruct(source: str) -> bool:
    """Flag selfdestruct without an access control guard in the same function."""
    HAS_GUARD = re.compile(
        r'require\s*\(\s*msg\.sender\s*==|onlyOwner|onlyAdmin|require\s*\(\s*owner'
    )
    for func in _get_function_blocks(source):
        if re.search(r'\bselfdestruct\b', func["body"]):
            if not HAS_GUARD.search(func["body"]):
                return True
    return False


def _check_locked_ether(source: str) -> bool:
    """Flag contract with payable but no way to withdraw."""
    has_payable  = bool(re.search(r'\bpayable\b', source))
    has_withdraw = bool(re.search(
        r'function\s+(withdraw|sendEther|transferOut|rescue)', source, re.I
    ))
    has_send_out = bool(re.search(
        r'\.(transfer|send)\s*\(|\.call\s*\{[^}]*value', source
    ))
    return has_payable and not has_withdraw and not has_send_out


def _check_timestamp_dependence(source: str) -> bool:
    """Flag block.timestamp inside if/require/while conditions."""
    return bool(re.search(
        r'(if|require|while)\s*\([^)]*block\.timestamp', source
    ))


def _find_line(source: str, pattern: str) -> int:
    """Return 1-indexed line number of first pattern match."""
    m = re.search(pattern, source)
    if m:
        return source[:m.start()].count('\n') + 1
    return 0


def run_pattern_scan(source: str) -> list[dict]:
    """Layer 1: pure-Python scan. Always runs, no external dependencies."""
    findings = []
    for rule in PATTERNS:
        matched = False

        if rule["pattern"] and re.search(rule["pattern"], source):
            matched = True
        if rule["extra_check"] and rule["extra_check"](source):
            matched = True

        if matched:
            line = 0
            if rule["pattern"]:
                line = _find_line(source, rule["pattern"])

            findings.append({
                "name":        rule["name"],
                "severity":    rule["severity"],
                "confidence":  rule["confidence"],
                "swc":         rule["swc"],
                "description": rule["description"],
                "fix":         rule["fix"],
                "source":      "pattern-scan",
                "lines":       [{"line": line}] if line else [],
            })
    return findings

# ─── Layer 1: Pure Python pattern scanner ─────────────────────────────────────
PATTERNS = [
    {
        "id":          "reentrancy",
        "name":        "reentrancy",
        "severity":    "High",
        "confidence":  "Medium",
        "swc":         "SWC-107",
        "description": "External call detected before state update. Classic reentrancy pattern: "
                       ".call{value:...} appears before balance/state modification.",
        "fix":         FIX_MAP["reentrancy-eth"],
        # matches: .call{value:...}(...) anywhere in source
        "pattern":     r'\.call\s*\{[^}]*value\s*:',
        # extra check: state mutation appears AFTER the call
        "extra_check": lambda src: bool(re.search(r'\.call\s*\{[^}]*value\s*:', src))
                                   and bool(re.search(r'balances?\[|_balance\s*[-+]=|amount\s*[-+]=', src)),
    },
    {
        "id":          "tx-origin",
        "name":        "tx-origin authentication",
        "severity":    "Medium",
        "confidence":  "High",
        "swc":         "SWC-115",
        "description": "tx.origin is used for authentication. This is exploitable via phishing: "
                       "an attacker contract can trick the owner into sending a transaction, "
                       "then forward it to use the owner's tx.origin.",
        "fix":         FIX_MAP["tx-origin"],
        "pattern":     r'\btx\.origin\b',
        "extra_check": None,
    },
    {
        "id":          "missing-access-control",
        "name":        "missing access control",
        "severity":    "High",
        "confidence":  "Medium",
        "swc":         "SWC-105",
        "description": "Sensitive function (owner change, mint, withdraw, upgrade, pause) "
                       "is public/external but lacks onlyOwner/require(msg.sender==owner) guard.",
        "fix":         "Add require(msg.sender == owner, 'Not authorized') or use "
                       "OpenZeppelin Ownable with the onlyOwner modifier.",
        "pattern":     None,  # handled in extra_check
        "extra_check": _check_missing_access_control,
    },
    {
        "id":          "unchecked-call",
        "name":        "unchecked low-level call",
        "severity":    "Medium",
        "confidence":  "High",
        "swc":         "SWC-104",
        "description": "Return value of a low-level .call() is not checked. "
                       "Failed calls will be silently ignored.",
        "fix":         FIX_MAP["unchecked-lowlevel"],
        "pattern":     None,
        "extra_check": _check_unchecked_call,
    },
    {
        "id":          "integer-overflow",
        "name":        "integer overflow/underflow",
        "severity":    "High",
        "confidence":  "Medium",
        "swc":         "SWC-101",
        "description": "Arithmetic without overflow protection on Solidity <0.8.0. "
                       "Integer overflow can wrap around and corrupt balances.",
        "fix":         FIX_MAP["integer-overflow"],
        "pattern":     None,
        "extra_check": _check_integer_overflow,
    },
    {
        "id":          "weak-prng",
        "name":        "weak randomness",
        "severity":    "High",
        "confidence":  "High",
        "swc":         "SWC-120",
        "description": "block.timestamp or blockhash used as a source of randomness. "
                       "Miners can manipulate these values.",
        "fix":         FIX_MAP["weak-prng"],
        "pattern":     r'\b(block\.timestamp|block\.blockhash|blockhash\s*\()\b',
        "extra_check": None,
    },
    {
        "id":          "selfdestruct",
        "name":        "unprotected selfdestruct",
        "severity":    "High",
        "confidence":  "Medium",
        "swc":         "SWC-106",
        "description": "selfdestruct() called without strict access control. "
                       "Anyone could destroy the contract and drain its ETH.",
        "fix":         FIX_MAP["suicidal"],
        "pattern":     None,
        "extra_check": _check_selfdestruct,
    },
    {
        "id":          "delegatecall",
        "name":        "dangerous delegatecall",
        "severity":    "High",
        "confidence":  "Medium",
        "swc":         "SWC-112",
        "description": "delegatecall to a potentially user-controlled address detected. "
                       "This can allow complete takeover of contract storage.",
        "fix":         FIX_MAP["controlled-delegatecall"],
        "pattern":     r'\.delegatecall\s*\(',
        "extra_check": None,
    },
    {
        "id":          "locked-ether",
        "name":        "locked ether",
        "severity":    "Medium",
        "confidence":  "Medium",
        "swc":         "SWC-132",
        "description": "Contract has payable functions but no withdrawal mechanism. "
                       "ETH sent to this contract may be permanently locked.",
        "fix":         FIX_MAP["locked-ether"],
        "pattern":     None,
        "extra_check": _check_locked_ether,
    },
    {
        "id":          "timestamp-dependence",
        "name":        "timestamp dependence",
        "severity":    "Low",
        "confidence":  "Medium",
        "swc":         "SWC-116",
        "description": "block.timestamp used in a conditional. "
                       "Miners can manipulate this by ~900 seconds.",
        "fix":         FIX_MAP["timestamp"],
        "pattern":     None,
        "extra_check": _check_timestamp_dependence,
    },
]
# ─── Layer 2: Slither ─────────────────────────────────────────────────────────
def _install_solc(version: str) -> str:
    """Install solc version if needed, return binary path."""
    try:
        import py_solc_x as solcx
        installed = [str(v) for v in solcx.get_installed_solc_versions()]
        if version not in installed:
            solcx.install_solc(version)
        solcx.set_solc_version(version)
        return str(solcx.get_solc_binary_path(version))
    except Exception as e:
        return ""


def run_slither(source: str, solc_version: str = None) -> dict:
    """Layer 2: Slither. Returns findings + diagnostic info."""
    # Auto-detect pragma version
    if not solc_version:
        m = re.search(r'pragma solidity\s*[\^~>=<]*(\d+\.\d+\.\d+)', source)
        solc_version = m.group(1) if m else "0.8.19"

    slither_bin = shutil.which("slither")
    if not slither_bin:
        return {
            "detectors": [],
            "error":     "slither not in PATH — run: pip install slither-analyzer",
            "ran":       False,
        }

    solc_path = _install_solc(solc_version)

    tmp_dir  = tempfile.mkdtemp(prefix="slither_")
    tmp_file = os.path.join(tmp_dir, "contract.sol")
    try:
        Path(tmp_file).write_text(source, encoding="utf-8")

        cmd = [slither_bin, tmp_file, "--json", "-", "--disable-color", "--no-fail-pedantic"]
        if solc_path:
            cmd += ["--solc", solc_path]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90, cwd=tmp_dir)

        stdout = proc.stdout.strip()
        if not stdout:
            return {
                "detectors": [],
                "error":     f"Slither no output. stderr: {proc.stderr.strip()[:400]}",
                "ran":       True,
            }

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {"detectors": [], "error": f"Slither bad JSON: {stdout[:200]}", "ran": True}

        raw = (data.get("results", {}).get("detectors", [])
               or data.get("detectors", []))

        findings = []
        for det in raw:
            lines = []
            for el in det.get("elements", []):
                lns = el.get("source_mapping", {}).get("lines", [])
                if lns:
                    lines.append({"line": lns[0], "all_lines": lns})
            check = det.get("check", "")
            findings.append({
                "name":        check,
                "severity":    det.get("impact", "Unknown"),
                "confidence":  det.get("confidence", "Unknown"),
                "swc":         SLITHER_TO_SWC.get(check, ""),
                "description": det.get("description", "").strip(),
                "fix":         FIX_MAP.get(check, "Refer to SWC registry for remediation."),
                "source":      "slither",
                "lines":       lines,
            })

        return {"detectors": findings, "error": None, "ran": True}

    except subprocess.TimeoutExpired:
        return {"detectors": [], "error": "Slither timed out (90s)", "ran": True}
    except Exception as e:
        return {"detectors": [], "error": str(e), "ran": True}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ─── Combined entry point ──────────────────────────────────────────────────────
def analyze_contract(source: str, solc_version: str = None) -> dict:
    """
    Run both layers and merge. Pattern scan always runs.
    Slither findings are added if available and not duplicates.
    """
    pattern_findings = run_pattern_scan(source)
    slither_result   = run_slither(source, solc_version)
    slither_findings = slither_result.get("detectors", [])

    # Deduplicate: skip Slither finding if pattern scan already caught same SWC
    pattern_swcs = {f["swc"] for f in pattern_findings if f["swc"]}
    merged = list(pattern_findings)
    for sf in slither_findings:
        if sf["swc"] not in pattern_swcs:
            merged.append(sf)

    return {
        "detectors":      merged,
        "slither_ran":    slither_result.get("ran", False),
        "slither_error":  slither_result.get("error"),
        "solc_version":   solc_version or "auto",
    }
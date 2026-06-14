# backend/analyzer/fix_suggestions.py
FIX_MAP = {
    "reentrancy": {
        "title":       "Reentrancy guard required",
        "description": "External calls are made before state updates.",
        "fix":         """Add OpenZeppelin ReentrancyGuard:
  import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

  contract Safe is ReentrancyGuard {
      function withdraw(uint256 amount) external nonReentrant {
          balances[msg.sender] -= amount;    // update state FIRST
          (bool ok,) = msg.sender.call{value: amount}("");
          require(ok);
      }
  }""",
        "swc": "SWC-107"
    },
    "integer_overflow": {
        "title":       "Integer overflow / underflow",
        "description": "Arithmetic operations can overflow without SafeMath or Solidity 0.8+.",
        "fix":         "Use Solidity >= 0.8.0 (checked arithmetic by default) or OpenZeppelin SafeMath.",
        "swc": "SWC-101"
    },
    "tx_origin": {
        "title":       "tx.origin authentication",
        "description": "tx.origin can be spoofed in phishing attacks.",
        "fix":         "Replace tx.origin with msg.sender for authentication checks.",
        "swc": "SWC-115"
    },
    "access_control": {
        "title":       "Missing access control",
        "description": "Critical functions lack owner/role checks.",
        "fix":         "Use OpenZeppelin Ownable or AccessControl — add onlyOwner/onlyRole modifiers.",
        "swc": "SWC-105"
    }
}

def get_fix(vuln_type: str) -> dict:
    return FIX_MAP.get(vuln_type, {
        "title": "Unknown vulnerability",
        "description": "Manual review recommended.",
        "fix": "Consult the SWC registry at swcregistry.io",
        "swc": "N/A"
    })
# backend/analyzer/ast_features.py
import  solcx
import json, re
from collections import defaultdict

def install_solc(version: str = "0.8.19"):
    if version not in solcx.get_installed_solc_versions():
        solcx.install_solc(version)
    solcx.set_solc_version(version)

def extract_ast_features(contract_source: str) -> dict:
    """Extract numeric features from Solidity AST for ML model input."""
    install_solc()
    
    try:
        compiled = solcx.compile_source(
            contract_source,
            output_values=["ast"],
            solc_version="0.4.24"
        )
    except Exception as e:
        return {"error": str(e), "features": None}

    features = defaultdict(int)

    for contract_name, data in compiled.items():
        ast = data.get("ast", {})
        _walk_ast(ast, features)

    return dict(features)

def _walk_ast(node: dict, features: defaultdict):
    if not isinstance(node, dict):
        return

    node_type = node.get("nodeType", "")

    # Count dangerous patterns
    if node_type == "ExpressionStatement":
        features["expression_statements"] += 1
    if node_type == "FunctionCall":
        expr = node.get("expression", {})
        # call() / send() / transfer()
        if expr.get("memberName") in ("call", "send", "transfer"):
            features["external_calls"] += 1
        if expr.get("memberName") == "call":
            features["raw_calls"] += 1          # highest risk

    if node_type == "IfStatement":
        features["if_statements"] += 1
    if node_type == "ForStatement":
        features["for_loops"] += 1
    if node_type == "EmitStatement":
        features["events_emitted"] += 1

    # State variable assignments
    if node_type == "Assignment":
        features["assignments"] += 1

    # tx.origin usage
    if str(node).find("tx.origin") != -1:
        features["tx_origin_usage"] += 1

    # Selfdestruct
    if str(node).find("selfdestruct") != -1:
        features["selfdestruct_calls"] += 1

    # Recursive walk
    for val in node.values():
        if isinstance(val, dict):
            _walk_ast(val, features)
        elif isinstance(val, list):
            for item in val:
                _walk_ast(item, features)
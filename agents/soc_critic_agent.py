#!/usr/bin/env python3
import ast
import sys
import os
import argparse

class SOCCriticVisitor(ast.NodeVisitor):
    def __init__(self, filepath, phase):
        self.filepath = filepath
        self.phase = phase
        self.errors = []
        self.in_analyze = False
        
        # Determine active lenses based on phase
        self.check_structural = phase in ["structural", "deep_sweep"]
        self.check_logical = phase in ["logical", "deep_sweep"]
        self.check_evasion = phase in ["evasion", "deep_sweep"]
        self.check_operational = phase in ["operational", "deep_sweep"]

    def report(self, message, lineno):
        self.errors.append(f"COMMAND [{self.filepath}:{lineno}]: {message}")

    def visit_FunctionDef(self, node):
        if node.name == 'analyze':
            self.in_analyze = True
            
            if self.check_structural:
                # Structural Lens: try-except inside loops
                for stmt in node.body:
                    if isinstance(stmt, ast.For):
                        has_try = any(isinstance(s, ast.Try) for s in stmt.body)
                        if not has_try:
                            self.report("Structural Phase: Main loop in analyze() is missing a try-except block. A single malformed event will crash the agent.", stmt.lineno)
            
            self.generic_visit(node)
            self.in_analyze = False
        else:
            self.generic_visit(node)

    def visit_Call(self, node):
        if self.check_operational:
            # Operational Lens: Check get_events_since size parameter
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'get_events_since':
                size_safe = False
                for kw in node.keywords:
                    if kw.arg == 'size':
                        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                            if kw.value.value >= 10000:
                                size_safe = True
                if not size_safe:
                    self.report("Operational Phase (Log Flooding): get_events_since is called without a safe size (>= 10000). Attackers can flood logs to push malicious events out of the query window.", node.lineno)
        
        if self.check_logical:
            # Logical Lens: Null pointer via event.get without `or {}`
            # Look for: event.get("something", {}).get("other") 
            # In AST: Call(Attribute(Call(Attribute(Name("event"), "get")), "get"))
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'get':
                if isinstance(node.func.value, ast.Call) and isinstance(node.func.value.func, ast.Attribute) and node.func.value.func.attr == 'get':
                    # It's a chained .get().get(). 
                    # If the inner get does not use an explicit fallback `or {}`, it might return None if the JSON value is explicitly null.
                    # Wait, in AST `event.get("x", {}).get("y")`, the fallback `{}` is inside the first get args.
                    # If JSON has {"x": null}, event.get("x", {}) returns None, so None.get() crashes.
                    self.report("Logical Phase (Null Pointer): Chained .get().get() found. If the first key exists but is 'null' in JSON, it returns None, causing AttributeError on the second .get(). Use 'event.get(key) or {}'.", node.lineno)
                    
            # Logical Lens: lower() on potentially None object
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'lower':
                # e.g., full_log.lower()
                # We can't perfectly trace full_log, but if it's a Call to .get() directly chained without fallback
                if isinstance(node.func.value, ast.Call) and isinstance(node.func.value.func, ast.Attribute) and node.func.value.func.attr == 'get':
                    # event.get("x").lower()
                    if len(node.func.value.args) < 2:
                        self.report("Logical Phase (Null Pointer): Calling .lower() directly on .get() without a default fallback. Can cause AttributeError if the key is missing or null.", node.lineno)

        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value:
            self._check_assignment_value(node.value, node.lineno)
        self.generic_visit(node)

    def visit_Assign(self, node):
        self._check_assignment_value(node.value, node.lineno)
        self.generic_visit(node)

    def _check_assignment_value(self, val, lineno):
        def is_subscripted_split(n):
            if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Call) and getattr(n.value.func, 'attr', '') == 'split':
                return True
            if isinstance(n, ast.Subscript):
                return is_subscripted_split(n.value)
            return False

        def has_strip(n):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and getattr(n.func, 'attr', '') == 'strip':
                return True
            if isinstance(n, ast.IfExp):
                return has_strip(n.body) and has_strip(n.orelse)
            return False

        if self.check_evasion:
            if is_subscripted_split(val):
                if not has_strip(val):
                    self.report("Evasion Phase (Trailing Whitespace): A string is split to extract a value, but .strip() is not used. Attackers can evade detection using trailing spaces.", lineno)

            def has_event_get(n):
                if isinstance(n, ast.Call) and getattr(n.func, 'attr', '') == 'get':
                    if n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == 'event':
                        return True
                if isinstance(n, ast.Call) and getattr(n.func, 'attr', '') == 'lower':
                    return False
                return False

            if has_event_get(val):
                if not (isinstance(val, ast.Call) and getattr(val.func, 'attr', '') == 'lower'):
                    self.report("Evasion Phase (Case Sensitivity): Event type extraction using .get('event') is not immediately followed by .lower().", lineno)

def run_critic(filepath, phase):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        sys.exit(1)

    with open(filepath, 'r', encoding='utf-8') as f:
        source = f.read()

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"COMMAND [Syntax Error]: Cannot parse {filepath} - {e}")
        sys.exit(1)

    visitor = SOCCriticVisitor(filepath, phase)
    visitor.visit(tree)

    if not visitor.errors:
        print(f"[CRITIC APPROVED] ZERO ERRORS FOUND IN PHASE: {phase.upper()}.")
        sys.exit(0)
    else:
        print(f"[CRITIC FAILED] The following vulnerabilities were found in phase {phase.upper()}:")
        for err in visitor.errors:
            print(err)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SOC Critic Agent')
    parser.add_argument('file', help='Target file to audit')
    parser.add_argument('--phase', choices=['structural', 'logical', 'evasion', 'operational', 'deep_sweep'], required=True, help='Audit phase to run')
    args = parser.parse_args()
    run_critic(args.file, args.phase)

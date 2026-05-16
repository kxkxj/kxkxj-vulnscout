from vulnscout.scanner.analyzer import _rule_check


def test_rule_check_detects_hardcoded_credential():
    code = "password = 'super_secret_123'"
    findings = _rule_check("config.py", code, "python")
    assert len(findings) >= 1
    assert findings[0]["cwe_id"] == "CWE-798"


def test_rule_check_detects_eval():
    code = "result = eval(user_input)"
    findings = _rule_check("danger.py", code, "python")
    assert len(findings) >= 1
    assert findings[0]["cwe_id"] == "CWE-95"


def test_rule_check_clean_code():
    code = "x = 1 + 2\nprint('hello')"
    findings = _rule_check("safe.py", code, "python")
    assert len(findings) == 0


def test_rule_check_js_hardcoded():
    code = "const API_KEY = 'sk-abc123'"
    findings = _rule_check("config.js", code, "javascript")
    assert len(findings) >= 1


def test_rule_check_cpp_strcpy():
    code = 'strcpy(buffer, user_input);'
    findings = _rule_check("main.cpp", code, "cpp")
    assert len(findings) >= 1
    assert findings[0]["cwe_id"] == "CWE-121"


def test_rule_check_java_command_injection():
    code = 'Runtime.getRuntime().exec("rm -rf /");'
    findings = _rule_check("Main.java", code, "java")
    assert len(findings) >= 1
    assert findings[0]["cwe_id"] == "CWE-78"

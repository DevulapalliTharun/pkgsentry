import base64
import warnings
import zlib
from pathlib import Path
from textwrap import dedent

from pkgsentry.analyzers.hooks import find_hooks
from pkgsentry.analyzers.obfuscation import scan_obfuscation
from pkgsentry.analyzers.rules import check_code
from pkgsentry.analyzers.typosquat import Popular

POPULAR = (Popular("requests", 1, 10**9),)


def scan(root: Path, files: dict[str, str]):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))
    hooks = find_hooks(root, "demo", "sdist", POPULAR)
    code = check_code(root, "sdist", hooks)
    return scan_obfuscation(root, "sdist", hooks, code)


def test_encoded_python_literal_is_reported_but_not_executed(tmp_path):
    code = "import subprocess; subprocess.run(['ls'])\n" * 4
    encoded = base64.b64encode(code.encode()).decode()
    findings = scan(tmp_path, {
        "demo-1.0/demo/__init__.py": f"""\
            import base64
            payload = "{encoded}"
            decoded = base64.b64decode(payload)
            """,
    })
    encoded = next(f for f in findings if f.rule == "encoded code")
    assert (encoded.context, encoded.strength, encoded.line) == ("call", "weak", 2)
    assert "code-like" in encoded.detail


def test_base64_wrapped_compressed_code_is_bounded_and_only_parsed(tmp_path):
    code = ("import subprocess; subprocess.run(['ls'])\n" * 100).encode()
    encoded = base64.b64encode(zlib.compress(code)).decode()
    findings = scan(tmp_path, {"demo-1.0/demo/payload.py": f"blob = \"{encoded}\"\n"})
    assert [(f.rule, f.context, f.strength) for f in findings] == [("encoded code", "call", "weak")]


def test_decoded_parser_warnings_do_not_leak(tmp_path):
    source = b"value = '" + bytes([92]) + b"{'\n"
    encoded = base64.b64encode(source).decode()
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        scan(tmp_path, {"demo-1.0/demo/payload.py": f"blob = \"{encoded}\"\n"})
    assert seen == []


def test_high_entropy_data_is_only_a_weak_hint(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/data.py": 'BLOB = "' + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 4 + '"\n'})
    encoded = next(f for f in findings if f.rule == "encoded string")
    assert encoded.strength == "weak"


def test_ordinary_string_and_short_base64_are_quiet(tmp_path):
    findings = scan(tmp_path, {
        "demo-1.0/demo/data.py": """\
            MESSAGE = "This is a normal message with words and punctuation."
            ICON = "iVBORw0KGgo="
            """,
    })
    assert findings == []


def test_chr_join_passed_to_exec_is_reported(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/setup.py": """\
        from setuptools import setup
        exec("".join(chr(n) for n in [112, 114, 105, 110, 116]))
        setup(name="demo")
        """})
    built = next(f for f in findings if f.rule == "string-built exec")
    assert (built.context, built.strength, built.line) == ("install", "strong", 2)


def test_invisible_bidi_and_zero_width_characters(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/setup.py": "from setuptools import setup\nname = 'payl\u202ead'\nsetup(name='demo')\n"})
    hidden = next(f for f in findings if f.rule == "invisible unicode")
    assert (hidden.context, hidden.strength, hidden.line) == ("install", "medium", 2)
    assert "U+202E" in hidden.detail


def test_normal_unicode_text_is_not_flagged(tmp_path):
    assert scan(tmp_path, {"demo-1.0/demo/text.py": 'label = "Árvíztűrő tükörfúrógép"\n'}) == []


def test_legitimate_zero_width_text_is_not_flagged(tmp_path):
    assert scan(tmp_path, {
        "demo-1.0/demo/text.py": 'emoji = "👩‍💻"\nregex = "[\u17b4-\u17b5]"\n# pip note: CPython ≥ 3.12.\u200b\n',
    }) == []


def test_bidi_control_in_comment_is_reported(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/text.py": "# hidden label \u202e\nvalue = 1\n"})
    hidden = next(f for f in findings if f.rule == "invisible unicode")
    assert (hidden.line, hidden.strength) == (1, "weak")
    assert "U+202E" in hidden.detail


def test_evidence_is_the_line_python_reads(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/text.py": "# a\u2028b\nlabel = 'x\u202ey'\n"})
    hidden = next(f for f in findings if f.rule == "invisible unicode")
    assert (hidden.line, hidden.evidence) == (2, "label = 'x\u202ey'")


def test_declared_source_encoding_does_not_hide_a_file(tmp_path):
    encoded = base64.b64encode(("import subprocess; subprocess.run(['ls'])\n" * 4).encode()).decode()
    path = tmp_path / "demo-1.0/demo/__init__.py"
    path.parent.mkdir(parents=True)
    # Valid Python because of the coding line, but not valid UTF-8 because of the byte 0xE9.
    path.write_bytes(f"# -*- coding: latin-1 -*-\n# caf\xe9\npayload = \"{encoded}\"\n".encode("latin-1"))
    assert [(f.rule, f.line) for f in scan(tmp_path, {})] == [("encoded code", 3)]


def test_tokenizer_memory_error_falls_back_to_bidi_scan(tmp_path, monkeypatch):
    import pkgsentry.analyzers.obfuscation as obfuscation

    def fail(_):
        raise MemoryError

    monkeypatch.setattr(obfuscation.tokenize, "generate_tokens", fail)
    findings = scan(tmp_path, {"demo-1.0/demo/text.py": "# hidden \u202e\nvalue = 1\n"})
    hidden = next(f for f in findings if f.rule == "invisible unicode")
    assert (hidden.line, hidden.detail.startswith("contains invisible")) == (1, True)


def test_compiled_only_python_module_is_reported(tmp_path):
    path = tmp_path / "demo-1.0/demo/__pycache__/payload.cpython-314.pyc"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"not executed or unmarshaled")
    findings = scan_obfuscation(tmp_path, "sdist", [], [])
    assert len(findings) == 1
    assert (findings[0].rule, findings[0].strength, findings[0].path) == (
        "compiled-only module", "weak", "demo-1.0/demo/__pycache__/payload.cpython-314.pyc")


def test_bytecode_with_source_is_not_flagged(tmp_path):
    source = tmp_path / "demo-1.0/demo/payload.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1\n")
    bytecode = source.parent / "__pycache__/payload.cpython-314.pyc"
    bytecode.parent.mkdir()
    bytecode.write_bytes(b"opaque bytes")
    assert scan_obfuscation(tmp_path, "sdist", [], []) == []


def test_development_context_is_informational(tmp_path):
    encoded = base64.b64encode((b"import subprocess; subprocess.run(['ls'])\n" * 4)).decode()
    findings = scan(tmp_path, {
        "demo-1.0/tests/test_payload.py": f"payload = \"{encoded}\"\nimport subprocess\nsubprocess.run(['ls'])\n",
    })
    assert findings
    assert all(f.context == "dev" and f.strength == "info" for f in findings)

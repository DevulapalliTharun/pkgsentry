from pathlib import Path
from textwrap import dedent

from pkgsentry.analyzers.hooks import find_hooks
from pkgsentry.analyzers.typosquat import Popular
from pkgsentry.cli import format_hooks

POPULAR = (
    Popular("requests", 1, 10**9),
    Popular("setuptools", 2, 10**9),
    Popular("wheel", 3, 10**8),
    Popular("jellyfish", 4, 10**7),
)


def scan(root: Path, files: dict[str, str], kind: str = "sdist", package: str = "demo"):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))
    return find_hooks(root, package, kind, POPULAR)


def summary(hooks):
    return [(h.kind, h.strength) for h in hooks]


def test_plain_setup_py_runs_even_on_download(tmp_path):
    hooks = scan(tmp_path, {"demo-1.0/setup.py": "from setuptools import setup\nsetup(name='demo')\n"})
    assert [(h.kind, h.when, h.strength, h.path) for h in hooks] == [
        ("setup.py", "download", "info", "demo-1.0/setup.py")
    ]


def test_custom_install_step(tmp_path):
    hooks = scan(tmp_path, {"demo-1.0/setup.py": """\
        from setuptools import setup
        from setuptools.command.install import install

        class PostInstall(install):
            def run(self):
                install.run(self)

        setup(name="demo", cmdclass={"install": PostInstall})
        """})
    step = next(h for h in hooks if h.kind == "custom 'install' step")
    assert (step.when, step.strength, step.line) == ("install", "medium", 4)
    assert "class PostInstall" in step.detail


def test_custom_step_found_through_import_alias(tmp_path):
    hooks = scan(tmp_path, {"demo-1.0/setup.py": """\
        import setuptools.command.egg_info as ei
        from setuptools import setup
        class Meta(ei.egg_info):
            pass
        setup(name="demo")
        """})
    step = next(h for h in hooks if h.kind == "custom 'egg_info' step")
    assert (step.when, step.strength, step.line) == ("download", "medium", 3)


def test_unrelated_class_named_install_counts_only_when_registered(tmp_path):
    source = """\
        from mylib import install
        from setuptools import setup
        class Helper(install):
            pass
        setup(name="demo"{})
        """
    assert summary(scan(tmp_path / "a", {"demo-1.0/setup.py": source.format("")})) == [("setup.py", "info")]
    registered = scan(tmp_path / "b", {"demo-1.0/setup.py": source.format(", cmdclass={'install': Helper}")})
    assert ("custom 'install' step", "medium") in summary(registered)


def test_extra_command_is_not_a_replaced_step(tmp_path):
    hooks = scan(tmp_path, {"demo-1.0/setup.py": """\
        from setuptools import setup
        from setuptools.command.install import install
        class VerifyVersion(install):
            pass
        setup(name="demo", cmdclass={"verify": VerifyVersion})
        """})
    assert summary(hooks) == [("setup.py", "info")]


def test_registering_setuptools_own_class_replaces_nothing(tmp_path):
    hooks = scan(tmp_path, {"demo-1.0/setup.py": """\
        from setuptools import setup
        from setuptools.command.install import install
        from setuptools.command.develop import develop
        from demo_build.commands import Metadata

        def wrap(command):
            return command

        setup(name="demo", cmdclass={
            "install": install,
            "develop": wrap(develop),
            "egg_info": Metadata,
        })
        """})
    assert sorted((h.kind, h.line, h.detail.split(" replaces")[0]) for h in hooks if h.line) == [
        ("custom 'develop' step", 11, "a class built by wrap()"),
        ("custom 'egg_info' step", 12, "Metadata (defined outside setup.py)"),
    ]


def test_computed_cmdclass_and_local_modules(tmp_path):
    hooks = scan(tmp_path, {
        "demo-1.0/setup.py": "import versioneer\nfrom setuptools import setup\n"
                             "setup(name='demo', cmdclass=versioneer.get_cmdclass())\n",
        "demo-1.0/versioneer.py": "",
    })
    assert summary(hooks) == [
        ("setup.py", "info"),
        ("custom steps computed at run time", "info"),
        ("module run by setup.py", "info"),
    ]
    assert hooks[2].path == "demo-1.0/versioneer.py"


def test_python2_setup_py_cannot_be_checked(tmp_path):
    hooks = scan(tmp_path, {"demo-1.0/setup.py": "print 'installing'\n"})
    assert ("unreadable setup.py", "weak") in summary(hooks)


def test_setup_keywords_passed_through_a_variable(tmp_path):
    hooks = scan(tmp_path, {"demo-1.0/setup.py": """\
        from setuptools import setup
        OPTIONS = dict(entry_points={"console_scripts": ["ssh = demo:main"]}, install_requires=["reqeusts>=1.0"])
        setup(name="demo", **OPTIONS)
        """})
    assert ("command-jacking", "strong") in summary(hooks)
    assert ("dependency looks like a typosquat", "strong") in summary(hooks)


def test_in_tree_backend_and_build_requirements(tmp_path):
    hooks = scan(tmp_path, {
        "demo-1.0/pyproject.toml": """\
            [build-system]
            requires = ["setuptool", "wheel", "obscure-builder"]
            build-backend = "backend"
            backend-path = ["_build"]
            """,
        "demo-1.0/_build/backend.py": "",
    })
    assert sorted(summary(hooks)) == [
        ("build requirement looks like a typosquat", "strong"),
        ("in-tree build backend", "info"),
        ("uncommon build requirement", "weak"),
    ]
    assert next(h for h in hooks if h.kind == "in-tree build backend").path == "demo-1.0/_build/backend.py"


def test_command_jacking(tmp_path):
    pyproject = {"demo-1.0/pyproject.toml": """\
        [project.scripts]
        git = "demo:main"
        pip3 = "demo:main"
        ls2 = "demo:main"
        demo = "demo:main"
        """}
    jacked = scan(tmp_path / "a", pyproject)
    assert sorted(h.detail.split("'")[1] for h in jacked if h.kind == "command-jacking") == ["git", "pip3"]
    assert [h.detail.split("'")[1] for h in scan(tmp_path / "b", pyproject, package="pip")] == ["git"]


def test_steps_and_commands_declared_in_config_files(tmp_path):
    hooks = scan(tmp_path, {
        "demo-1.0/pyproject.toml": '[tool.setuptools.cmdclass]\ninstall = "demo.cmds.Install"\n',
        "demo-1.0/setup.cfg": """\
            [options]
            cmdclass =
                egg_info = demo.cmds.Meta
            [options.entry_points]
            console_scripts =
                curl = demo:main
            """,
    })
    assert sorted(summary(hooks)) == [
        ("command-jacking", "strong"),
        ("custom 'egg_info' step", "medium"),
        ("custom 'install' step", "medium"),
    ]


def test_wheel_startup_files_commands_and_dependencies(tmp_path):
    hooks = scan(tmp_path, {
        "demo-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: demo\nRequires-Dist: requests (>=2)\n"
                                       "Requires-Dist: jeIlyfish\n\nRequires-Dist: reqeusts is only description text\n",
        "demo-1.0.dist-info/entry_points.txt": "[console_scripts]\nls = demo:main\n",
        "demo-1.0.data/scripts/curl": "#!/bin/sh\n",
        "demo-1.0.data/purelib/extra.pth": "import extra\n",
        "demo_init.pth": "# comment\nimport demo_startup\n",
        "paths.pth": "/opt/demo/lib\n",
        "sitecustomize.py": "",
        "demo/sitecustomize.py": "",
        "demo/__init__.py": "",
    }, kind="wheel")
    assert sorted((h.kind, h.strength, h.path, h.line) for h in hooks) == [
        (".pth startup code", "medium", "demo-1.0.data/purelib/extra.pth", 1),
        (".pth startup code", "medium", "demo_init.pth", 2),
        ("command-jacking", "strong", "demo-1.0.data/scripts/curl", 0),
        ("command-jacking", "strong", "demo-1.0.dist-info/entry_points.txt", 0),
        ("dependency looks like a typosquat", "strong", "demo-1.0.dist-info/METADATA", 0),
        ("startup module", "strong", "sitecustomize.py", 0),
    ]


def test_sdist_metadata_files(tmp_path):
    hooks = scan(tmp_path, {
        "demo-1.0/PKG-INFO": "Metadata-Version: 2.1\nName: demo\nRequires-Dist: reqeusts\n",
        "demo-1.0/demo.egg-info/requires.txt": "requests>=2\ndemo[extra]\n\n[extra]\njellyfish\n",
        "demo-1.0/demo.egg-info/entry_points.txt": "[console_scripts]\nsudo = demo:main\n",
    })
    assert sorted(summary(hooks)) == [("command-jacking", "strong"), ("dependency looks like a typosquat", "strong")]


def test_optional_extras_are_not_checked(tmp_path):
    hooks = scan(tmp_path, {
        "demo-1.0/PKG-INFO": 'Metadata-Version: 2.1\nName: demo\nRequires-Dist: reqeusts; extra == "test"\n',
        "demo-1.0/demo.egg-info/requires.txt": "[test]\nreqeusts\n\n[:sys_platform == 'win32']\njeIlyfish\n",
    })
    assert [(h.kind, h.detail.split("'")[1]) for h in hooks] == [("dependency looks like a typosquat", "jeIlyfish")]


def test_sdist_startup_files_are_weaker_until_installed(tmp_path):
    hooks = scan(tmp_path, {
        "demo-1.0/setup.py": "from setuptools import setup\nsetup(name='demo', data_files=[('', ['demo.pth'])])\n",
        "demo-1.0/demo.pth": "import demo\n",
        "demo-1.0/sitecustomize.py": "",
        "demo-1.0/tests/data/other.pth": "import other\n",
    })
    assert sorted(summary(hooks)) == [
        (".pth file installed as data", "medium"),
        (".pth startup code", "weak"),
        ("setup.py", "info"),
        ("startup module", "medium"),
    ]


def test_archive_layout_cannot_disguise_an_sdist_as_a_wheel(tmp_path):
    hooks = scan(tmp_path, {
        "demo-1.0/setup.py": "from setuptools import setup\nsetup(name='demo')\n",
        "demo-1.0/fake.dist-info/METADATA": "Name: demo\n",
    })
    assert ("setup.py", "info") in summary(hooks)


def test_format_hooks_prints_attacker_text_safely(tmp_path):
    hooks = scan(tmp_path, {"\x1b[2Jevil.pth": "import x\n"}, kind="wheel")
    text = format_hooks("demo 1.0 (wheel)", hooks)
    assert "\x1b" not in text and "?[2Jevil.pth:1" in text
    assert "1 medium" in text and text.endswith("Nothing was installed or run.")

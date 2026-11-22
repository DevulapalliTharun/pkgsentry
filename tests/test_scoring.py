from datetime import datetime, timedelta, timezone

from pkgsentry.analyzers.hooks import Hook
from pkgsentry.analyzers.rules import Finding
from pkgsentry.analyzers.typosquat import NameCheck, Popular, TyposquatMatch
from pkgsentry.models import PackageInfo
from pkgsentry.scoring import score_package

NOW = datetime(2026, 11, 22, tzinfo=timezone.utc)
REQUESTS = Popular("requests", 8, 1_000_000_000)


def package(**changes):
    values = dict(
        name="example",
        version="1.0",
        summary="A useful package",
        author="Author",
        author_email="author@example.org",
        homepage="https://example.org",
        description_length=1000,
        release_count=12,
        first_upload=NOW - timedelta(days=365),
        files=(),
    )
    values.update(changes)
    return PackageInfo(**values)


def test_documented_fake_package_scores_92():
    fake = package(name="reqeusts", summary="", homepage="", description_length=0, release_count=1,
                   first_upload=NOW - timedelta(days=1))
    name_check = NameCheck(
        "reqeusts", "reqeusts", None, False,
        (TyposquatMatch(REQUESTS, "swapped letters", 1, "strong"),),
    )
    hooks = [Hook("install", "custom 'install' step", "setup.py", 5, "runs at install", "medium")]
    findings = [
        Finding("secret", "setup.py", 7, "install", "medium", "reads AWS credentials", "open(...)"),
        Finding("network", "setup.py", 8, "install", "medium", "uses the network", "urlopen(...)"),
        Finding("secret + network", "setup.py", 7, "install", "strong", "steals credentials", "open(...)"),
    ]

    result = score_package(fake, name_check, hooks, findings, now=NOW)

    assert (result.score, result.level) == (92, "critical")
    assert {signal.category: signal.points for signal in result.signals} == {
        "metadata": 12,
        "name": 20,
        "install": 20,
        "code": 30,
        "combination": 10,
    }


def test_mature_benign_package_scores_zero():
    result = score_package(package(), NameCheck("example", "example", REQUESTS, False, ()), [], [], now=NOW)
    assert (result.score, result.level, result.signals) == (0, "low", ())


def test_single_strong_typosquat_enters_guarded_band():
    check = NameCheck("reqeusts", "reqeusts", None, False,
                      (TyposquatMatch(REQUESTS, "swapped letters", 1, "strong"),))
    result = score_package(package(), check, [], [], now=NOW)
    assert (result.score, result.level) == (20, "guarded")


def test_repeated_findings_in_one_family_do_not_stack():
    name_check = NameCheck("example", "example", REQUESTS, False, ())
    one = Finding("network", "pkg/a.py", 1, "import", "medium", "network call", "get(url)")
    repeated = [one] + [Finding("network", f"pkg/{i}.py", i, "import", "medium", "network call", "get(url)")
                         for i in range(2, 20)]
    assert score_package(package(), name_check, [], [one], now=NOW).score == \
        score_package(package(), name_check, [], repeated, now=NOW).score


def test_metadata_signal_has_a_cap_and_is_time_bounded():
    fresh = package(summary="", author="", author_email="", homepage="", description_length=0,
                    release_count=1, first_upload=NOW - timedelta(days=1))
    old = package(summary="", author="", author_email="", homepage="", description_length=0,
                  release_count=1, first_upload=NOW - timedelta(days=90))
    future = package(summary="", author="", author_email="", homepage="", description_length=0,
                     release_count=1, first_upload=NOW + timedelta(days=1))
    fresh_result = score_package(fresh, NameCheck("x", "x", None, False, ()), [], [], now=NOW)
    old_result = score_package(old, NameCheck("x", "x", None, False, ()), [], [], now=NOW)
    future_result = score_package(future, NameCheck("x", "x", None, False, ()), [], [], now=NOW)
    assert fresh_result.score == 12
    assert old_result.score == 8
    assert future_result.score == 8


def test_zero_release_metadata_is_described_correctly():
    empty = package(release_count=0, first_upload=None)
    result = score_package(empty, NameCheck("x", "x", None, False, ()), [], [], now=NOW)
    assert "no published releases" in result.signals[0].detail


def test_score_never_exceeds_100():
    suspicious = package(name="reqeusts", summary="", author="", author_email="", homepage="",
                         description_length=0, release_count=1, first_upload=NOW)
    name_check = NameCheck("reqeusts", "reqeusts", None, True,
                           (TyposquatMatch(REQUESTS, "swapped letters", 1, "strong"),))
    hooks = [
        Hook("install", "custom 'install' step", "setup.py", 1, "custom install", "medium"),
        Hook("startup", "startup module", "sitecustomize.py", 1, "startup code", "strong"),
        Hook("command", "command-jacking", "entry_points.txt", 1, "replaces a command", "strong"),
    ]
    findings = [Finding("secret + network", "setup.py", 2, "install", "strong", "exfiltration", "..."),
                Finding("string-built exec", "setup.py", 3, "install", "strong", "hidden exec", "...")]
    assert score_package(suspicious, name_check, hooks, findings, now=NOW).score == 100


def test_weak_call_only_hint_stays_low():
    finding = Finding("encoded string", "pkg/data.py", 2, "call", "weak", "encoded blob", "...")
    result = score_package(package(), NameCheck("example", "example", REQUESTS, False, ()), [], [finding], now=NOW)
    assert (result.score, result.level) == (4, "low")
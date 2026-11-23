import hashlib
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from pkgsentry import cli
from pkgsentry.campaigns import Indicator
from pkgsentry.scoring import RiskSignal
from pkgsentry.storage import ensure_schema, load_package, load_scans, save_scan
from pkgsentry.triage.evidence import Excerpt
from pkgsentry.web import views
from pkgsentry.web.app import create_app

EVIL_NAME = "<script>alert(1)</script>"
EVIL_CODE = '"><script>alert(2)</script> https://c2.evil.example/x'
EVIL_DETAIL = "sends <img src=x onerror=alert(3)> away"
EVIL_URL = 'https://c2.evil.example/"><svg onload=alert(4)>'


def indicator(value, key):
    return Indicator("url", value, key, "demo-1.0/setup.py", 1, False)


def excerpt(code):
    return Excerpt("C1", "demo-1.0/setup.py", 1, (code,), (0,), (1,), ("network",))


def make_db(tmp_path):
    db = tmp_path / "history.db"
    signal = RiskSignal("code", 30, "strong", "install", EVIL_DETAIL, "demo-1.0/setup.py", 7)
    save_scan(db, "reqeusts", "1.0.2", "sdist", "ab" * 32, 92, "critical",
              [indicator(EVIL_URL, "host c2.evil.example"), indicator("https://github.com/x/y", "")],
              (signal,), [excerpt(EVIL_CODE)])
    save_scan(db, "colourama-x", "0.4.1", "sdist", "cd" * 32, 72, "critical",
              [indicator("https://c2.evil.example/v2", "host c2.evil.example")], (), [])
    save_scan(db, "reqeusts", "0.9", "wheel", "ef" * 32, 30, "guarded", [], (), [])
    save_scan(db, EVIL_NAME, "1.0", "sdist", "", 45, "high", [], (RiskSignal("name", 12, "medium", "name", "x", "", 0),), [])
    save_scan(db, "quiet", "2.0", "wheel", "", 3, "low", [], (), [])
    return db


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(make_db(tmp_path), ["testserver"]))


PAGES = ["/", "/?level=critical", "/?q=req", "/campaigns", "/package/reqeusts", "/package/nope"]


@pytest.mark.parametrize("page", PAGES + ["/api/overview", "/api/scans", "/api/campaigns", "/api/packages/reqeusts"])
def test_every_response_carries_the_security_headers(client, page):
    headers = client.get(page).headers
    assert headers["content-security-policy"] == (
        "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'")
    assert (headers["x-content-type-options"], headers["referrer-policy"], headers["cache-control"]) == (
        "nosniff", "no-referrer", "no-store")


@pytest.mark.parametrize("page", PAGES)
def test_attacker_text_is_shown_as_inert_text(client, page):
    text = client.get(page).text
    lowered = text.lower()
    assert "<script" not in lowered and "<img" not in lowered and "<svg onload" not in lowered
    assert "style=" not in lowered and "javascript:" not in lowered
    assert not re.search(r'(src|href)="https?://', text)  # nothing is loaded from, or links to, another site


def test_escaped_payloads_appear_as_text_on_the_page_that_shows_them(client):
    package = client.get("/package/reqeusts").text
    assert "&lt;img src=x onerror=alert(3)&gt;" in package
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in package
    assert "hxxps://c2[.]evil[.]example/x" in package  # the code line is defused like everything else
    assert "https://c2.evil.example" not in package
    assert "hxxps://c2[.]evil[.]example/&#34;&gt;&lt;svg onload=alert(4)&gt;" in package
    findings = client.get("/").text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in findings
    assert 'href="/package/<' not in findings  # the link target is percent-encoded, not raw


def test_search_and_filter_values_are_escaped_or_ignored(client):
    text = client.get("/", params={"q": '"><script>alert(5)</script>', "level": 'critical"><b>x</b>'}).text
    assert "<script" not in text.lower() and "<b>x" not in text
    assert 'value="&#34;&gt;&lt;script&gt;' in text
    assert "No scans match" in text


def test_the_history_file_is_never_changed_by_browsing(tmp_path):
    db = make_db(tmp_path)
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    client = TestClient(create_app(db, ["testserver"]))
    for page in PAGES + ["/api/scans", "/api/campaigns", "/api/packages/reqeusts"]:
        client.get(page)
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
@pytest.mark.parametrize("path", ["/", "/campaigns", "/package/reqeusts", "/api/scans", "/api/packages/reqeusts"])
def test_nothing_can_be_written_or_started_over_http(client, method, path):
    assert getattr(client, method)(path).status_code == 405


def test_a_foreign_host_header_is_refused_against_dns_rebinding(client):
    response = client.get("/", headers={"Host": "evil.example"})
    assert response.status_code == 400
    assert "content-security-policy" in response.headers


def test_package_names_are_validated_before_use(client):
    for name in ["..%2f..%2fetc%2fpasswd", "a%20b", "%3Cscript%3E", "x%00", "never-scanned"]:
        assert client.get(f"/package/{name}").status_code == 404
        api = client.get(f"/api/packages/{name}")
        assert api.status_code == 404 and set(api.json()) == {"detail"}
    assert client.get("/api/packages/never-scanned").json() == {"detail": "no such package"}


def test_a_stored_name_pypi_would_refuse_is_not_served(tmp_path):
    db = make_db(tmp_path)
    save_scan(db, "bad name", "1.0", "sdist", "", 10, "low", [])
    client = TestClient(create_app(db, ["testserver"]))
    assert client.get("/package/bad%20name").status_code == 404
    assert client.get("/api/packages/bad%20name").status_code == 404
    assert client.get("/package/quiet").status_code == 200


def test_interactive_api_docs_that_load_scripts_from_a_cdn_are_off(client):
    assert client.get("/docs").status_code == 404 and client.get("/redoc").status_code == 404
    assert "/api/scans" in client.get("/openapi.json").json()["paths"]


def test_overview_counts_and_filters(client):
    view = client.get("/api/overview").json()
    assert view == {"packages": 4, "scans": 5, "levels": {"low": 1, "guarded": 0, "high": 1, "critical": 2},
                    "campaigns": 1, "linked_packages": 2, "indicators": 1}
    assert [(s["package"], s["score"], s["campaign"]) for s in client.get("/api/scans", params={"level": "critical"}).json()
            ] == [("reqeusts", 92, 1), ("colourama-x", 72, 1)]
    assert [s["package"] for s in client.get("/api/scans", params={"q": "QUIET"}).json()] == ["quiet"]
    assert len(client.get("/api/scans", params={"level": "nonsense"}).json()) == 5  # an unknown level means all


def test_api_package_detail_has_evidence_and_defanged_addresses(client):
    scans = {s["version"]: s for s in client.get("/api/packages/reqeusts").json()}
    assert sorted(scans) == ["0.9", "1.0.2"]
    detail = scans["1.0.2"]
    assert detail["excerpts"] == [{"tag": "C1", "path": "demo-1.0/setup.py", "flagged_lines": [1], "rules": "network",
                                   "code": [">    1 | " + EVIL_CODE]}]
    assert [(i["value"], i["defanged"], i["key"]) for i in detail["indicators"]][0] == (
        EVIL_URL, 'hxxps://c2[.]evil[.]example/"><svg onload=alert(4)>', "host c2.evil.example")
    assert detail["signals"][0]["points"] == 30


def test_api_campaigns_list_the_shared_indicator(client):
    assert client.get("/api/campaigns").json() == [{
        "number": 1, "level": "critical", "packages": {"colourama-x": "critical", "reqeusts": "critical"},
        "links": [{"key": "host c2.evil.example", "packages": ["colourama-x", "reqeusts"]}]}]
    assert client.get("/api/campaigns").headers["content-type"].startswith("application/json")


def test_campaign_graph_is_drawn_from_numbers_and_escaped_text(client):
    page = client.get("/campaigns").text
    assert 'id="campaign-1"' in page and page.count('class="edge"') == 2
    assert re.findall(r'd="(M[\d. C-]+)"', page)  # path data is made of digits only


def test_older_scans_are_collapsed_and_every_package_has_a_page(client):
    page = client.get("/package/reqeusts").text
    assert page.count("<details") == 1 and "Related packages" in page and "colourama-x" in page


def test_the_dashboard_needs_an_existing_history(tmp_path):
    with pytest.raises(ValueError, match="no scan history"):
        create_app(tmp_path / "missing.db")
    assert not (tmp_path / "missing.db").exists()


def test_serve_refuses_a_remote_address_without_permission(tmp_path, monkeypatch, capsys):
    import uvicorn
    started = []  # a broken guard must fail this test, never open a real listener
    monkeypatch.setattr(uvicorn, "run", lambda app, **options: started.append(options))
    assert cli.main(["serve", "--db", str(make_db(tmp_path)), "--host", "0.0.0.0"]) == 1
    assert "refusing to listen on 0.0.0.0" in capsys.readouterr().err
    assert started == []
    assert cli.main(["serve", "--db", str(make_db(tmp_path)), "--host", "0.0.0.0", "--allow-remote"]) == 0
    assert started[0]["host"] == "0.0.0.0"


def test_serve_listens_on_this_machine_by_default(tmp_path, monkeypatch, capsys):
    import uvicorn
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **options: calls.append(options))
    assert cli.main(["serve", "--db", str(make_db(tmp_path)), "--port", "9001"]) == 0
    assert calls == [{"host": "127.0.0.1", "port": 9001, "log_level": "warning", "server_header": False}]
    assert "http://127.0.0.1:9001" in capsys.readouterr().out


def test_serve_without_a_history_explains_what_to_do(tmp_path, capsys):
    assert cli.main(["serve", "--db", str(tmp_path / "missing.db")]) == 1
    assert "no scan history" in capsys.readouterr().err


# Storage

def test_storage_round_trips_the_score_breakdown_and_excerpts(tmp_path):
    db = make_db(tmp_path)
    scan = next(s for s in load_package(db, "reqeusts") if s.version == "1.0.2")
    assert scan.signals == (RiskSignal("code", 30, "strong", "install", EVIL_DETAIL, "demo-1.0/setup.py", 7),)
    assert scan.sha256 == "ab" * 32
    [stored] = scan.excerpts
    assert (stored.tag, stored.flagged, stored.body) == ("C1", (1,), (">    1 | " + EVIL_CODE,))
    assert all(s.signals == () for s in load_scans(db))  # the list view skips the heavier parts
    assert next(s for s in load_scans(db, signals=True) if s.version == "1.0.2").signals == scan.signals


def test_reading_opens_the_history_read_only(tmp_path):
    db = make_db(tmp_path)
    from pkgsentry.storage import _connect
    connection = _connect(db)
    with pytest.raises(sqlite3.OperationalError):
        connection.execute("DELETE FROM scans")
    connection.close()
    assert len(load_scans(db)) == 5


def test_a_history_from_the_campaigns_step_keeps_working(tmp_path):
    db = tmp_path / "old.db"
    with sqlite3.connect(db) as connection:
        connection.executescript("""
            CREATE TABLE scans (id INTEGER PRIMARY KEY, package TEXT NOT NULL, version TEXT NOT NULL, kind TEXT NOT NULL,
                sha256 TEXT NOT NULL, score INTEGER NOT NULL, level TEXT NOT NULL, scanned_at TEXT NOT NULL,
                UNIQUE (package, version, kind));
            CREATE TABLE indicators (scan_id INTEGER NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, key TEXT NOT NULL,
                path TEXT NOT NULL, line INTEGER NOT NULL, hidden INTEGER NOT NULL);
            INSERT INTO scans VALUES (1, 'demo', '1.0', 'sdist', 'ab', 50, 'high', '2026-01-01T00:00:00+00:00');
        """)
    assert [s.package for s in load_scans(db)] == ["demo"]
    ensure_schema(db)
    [scan] = load_package(db, "demo")
    assert (scan.score, scan.signals, scan.excerpts) == (50, (), ())


# View model

def test_donut_slices_add_up_and_start_at_the_top(tmp_path):
    view = views.overview(load_scans(make_db(tmp_path)))
    assert [name for name, *_ in view.donut] == ["critical", "high", "guarded", "low"]
    assert sum(share for _, _, share, _ in view.donut) == pytest.approx(100, abs=0.05)
    assert view.donut[0][3] == 25.0  # the first slice starts at twelve o'clock


def test_only_known_levels_reach_css_class_names():
    assert [views.level_class(x) for x in ("critical", 'x" onclick="y', "")] == ["critical", "low", "low"]
    assert views.top_level(["low", "high", "guarded"]) == "high"
    assert views.top_level([]) == "low"


def test_related_packages_share_only_attacker_specific_keys(tmp_path):
    scans = load_scans(make_db(tmp_path))
    assert views.related(scans, "reqeusts") == [("colourama-x", "critical", ("host c2.evil.example",))]
    assert views.related(scans, "quiet") == []

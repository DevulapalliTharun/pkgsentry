from pkgsentry.analyzers.typosquat import Popular, check_name, edit_distance, normalize, popular_packages

POPULAR = (
    Popular("requests", 1, 1_000_000),
    Popular("numpy", 2, 900_000),
    Popular("python-dateutil", 3, 800_000),
    Popular("setuptools", 4, 700_000),
    Popular("six", 5, 600_000),
    Popular("jellyfish", 400, 50_000),
    Popular("tabulate", 500, 40_000),
    Popular("pyfiglet", 2500, 9_000),
)


def matches(name):
    return [(m.target.name, m.technique, m.strength) for m in check_name(name, POPULAR).matches]


def test_edit_distance():
    assert edit_distance("requests", "requests") == 0
    assert edit_distance("reqeusts", "requests") == 1  # two neighbouring letters swapped counts as one edit
    assert edit_distance("kitten", "sitting") == 3
    assert edit_distance("", "abc") == 3


def test_normalize_follows_pypi_rules():
    assert normalize("Python_Dateutil") == "python-dateutil"
    assert normalize("zope.interface") == "zope-interface"
    assert normalize("a-_.b") == "a-b"


def test_single_edits_are_named():
    assert matches("reqeusts") == [("requests", "swapped letters", "strong")]
    assert matches("requets") == [("requests", "missing letter", "strong")]
    assert matches("requestss") == [("requests", "extra letter", "strong")]
    assert matches("requezts") == [("requests", "changed letter", "strong")]


def test_two_edits_allowed_only_for_long_names():
    assert matches("pyhton-dateutill") == [("python-dateutil", "2 edits", "medium")]
    assert matches("reqeustss") == []  # 8-letter target allows one edit


def test_one_edit_from_a_less_popular_package_is_medium():
    assert matches("pyfiglett") == [("pyfiglet", "extra letter", "medium")]


def test_separator_trick():
    assert matches("pythondateutil") == [("python-dateutil", "separator trick", "strong")]
    assert matches("setup-tools") == [("setuptools", "separator trick", "strong")]


def test_swapped_words():
    assert matches("dateutil-python") == [("python-dateutil", "swapped words", "strong")]


def test_lookalike_characters():
    assert matches("nurnpy") == [("numpy", "look-alike characters", "strong")]  # rn looks like m
    assert matches("jeIlyfish") == [("jellyfish", "look-alike characters", "strong")]  # capital I, not l
    assert matches("requ3sts") == [("requests", "changed letter", "strong")]  # 3 for e: no look-alike rule, still 1 edit
    assert matches("setupt0ols") == [("setuptools", "look-alike characters", "strong")]  # zero, not o


def test_added_prefix_or_suffix():
    assert matches("python-requests") == [("requests", "added prefix 'python-'", "medium")]
    assert matches("tabulate-py") == [("tabulate", "added suffix '-py'", "weak")]


def test_popular_name_is_never_flagged():
    result = check_name("Requests", POPULAR)
    assert result.popular.rank == 1
    assert result.matches == ()


def test_short_names_are_not_judged_by_edit_distance():
    assert matches("sx") == []
    assert matches("siz") == []


def test_unrelated_names_are_quiet():
    assert matches("pkgsentry") == []
    assert matches("my-internal-tool") == []


def test_stdlib_module_names():
    assert check_name("crypt", POPULAR).stdlib_module  # removed in Python 3.13, still a squatting target
    assert check_name("pwd", POPULAR).stdlib_module
    assert not check_name("requests", POPULAR).stdlib_module


def test_snapshot_loads():
    popular = popular_packages()
    assert len(popular) == 5000
    assert [p.rank for p in popular[:3]] == [1, 2, 3]
    assert {"requests", "numpy", "boto3"} <= {p.name for p in popular}
    assert all(p.name == normalize(p.name) for p in popular)

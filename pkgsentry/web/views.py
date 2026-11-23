"""What the dashboard shows, computed from saved scans. Pure functions: no web framework in here."""

from dataclasses import dataclass

from pkgsentry.campaigns import link
from pkgsentry.scoring import LEVELS
from pkgsentry.storage import StoredScan

_GRAPH_ROW = 40
_GRAPH_PAD = 22
_KEY_X, _KEY_W = 20, 300
_PACKAGE_X, _PACKAGE_W = 470, 230
MAX_QUERY = 64


def level_class(level: str) -> str:
    """Only a known level may reach a CSS class name."""
    return level if level in LEVELS else "low"


def top_level(levels) -> str:
    return max(levels, key=lambda level: LEVELS.index(level_class(level)), default="low")


@dataclass(frozen=True)
class GraphNode:
    label: str
    level: str
    y: float


@dataclass(frozen=True)
class Graph:
    width: int
    height: int
    key_x: int
    key_width: int
    package_x: int
    package_width: int
    node_height: int
    keys: tuple[GraphNode, ...]
    packages: tuple[GraphNode, ...]
    edges: tuple[str, ...]  # SVG path data, built from numbers only


@dataclass(frozen=True)
class CampaignView:
    number: int
    packages: tuple[str, ...]
    levels: dict[str, str]
    level: str  # the highest level of any member
    links: tuple[tuple[str, tuple[str, ...]], ...]
    graph: Graph


@dataclass(frozen=True)
class Row:
    scan: StoredScan
    categories: tuple[str, ...]
    linkable: int
    campaign: int | None
    campaign_size: int


@dataclass(frozen=True)
class Overview:
    packages: int
    scans: int
    levels: dict[str, int]  # packages by their highest level
    scan_levels: dict[str, int]  # scans by level, for the filter tabs
    campaigns: tuple[CampaignView, ...]
    linked_packages: int
    indicators: int
    rows: tuple[Row, ...]
    shown_level: str
    query: str
    donut: tuple[tuple[str, int, float, float], ...]  # (level, count, share, offset), shares in percent


def package_levels(scans: list[StoredScan]) -> dict[str, str]:
    levels: dict[str, str] = {}
    for scan in scans:
        levels[scan.package] = top_level([levels.get(scan.package, "low"), scan.level])
    return levels


def campaigns_from(scans: list[StoredScan]) -> list[CampaignView]:
    """Packages joined by attacker-specific indicators, most severe first."""
    keys: dict[str, set[str]] = {}
    for scan in scans:
        keys.setdefault(scan.package, set()).update(i.key for i in scan.indicators)
    levels = package_levels(scans)
    groups = sorted(link(keys), key=lambda c: (-LEVELS.index(level_class(top_level(levels[p] for p in c.packages))),
                                               -len(c.packages), c.packages))
    return [CampaignView(number, group.packages, {p: levels[p] for p in group.packages},
                         level_class(top_level(levels[p] for p in group.packages)), group.links,
                         _graph(group.packages, group.links, levels))
            for number, group in enumerate(groups, 1)]


def overview(scans: list[StoredScan], level: str = "", query: str = "") -> Overview:
    levels = package_levels(scans)
    campaigns = campaigns_from(scans)
    member = {name: (view.number, len(view.packages)) for view in campaigns for name in view.packages}
    query = query.strip()[:MAX_QUERY]
    wanted = level if level in LEVELS else ""
    rows = [Row(scan, tuple(dict.fromkeys(s.category for s in scan.signals if s.points)),
                sum(1 for i in scan.indicators if i.key), *member.get(scan.package, (None, 0)))
            for scan in sorted(scans, key=lambda s: (-s.score, s.package, s.version, s.kind))
            if (not wanted or level_class(scan.level) == wanted) and query.lower() in scan.package.lower()]
    counts = {name: sum(1 for value in levels.values() if level_class(value) == name) for name in LEVELS}
    scan_counts = {name: sum(1 for scan in scans if level_class(scan.level) == name) for name in LEVELS}
    total = max(1, sum(counts.values()))
    donut, offset = [], 25.0  # a circle of circumference 100 starts at the top when offset is 25
    for name in reversed(LEVELS):
        share = 100 * counts[name] / total
        donut.append((name, counts[name], round(share, 2), round(offset, 2)))
        offset -= share
    linkable = {i.key for scan in scans for i in scan.indicators if i.key}
    return Overview(len(levels), len(scans), counts, scan_counts, tuple(campaigns),
                    sum(len(c.packages) for c in campaigns), len(linkable), tuple(rows), wanted, query, tuple(donut))


def related(scans: list[StoredScan], package: str) -> list[tuple[str, str, tuple[str, ...]]]:
    """Other packages that share an attacker-specific indicator with this one: (name, level, shared keys)."""
    mine = {i.key for scan in scans if scan.package == package for i in scan.indicators if i.key}
    levels = package_levels(scans)
    shared: dict[str, set[str]] = {}
    for scan in scans:
        if scan.package != package:
            found = {i.key for i in scan.indicators if i.key} & mine
            if found:
                shared.setdefault(scan.package, set()).update(found)
    return sorted(((name, levels[name], tuple(sorted(keys))) for name, keys in shared.items()),
                  key=lambda item: (-LEVELS.index(level_class(item[1])), item[0]))


def _graph(packages: tuple[str, ...], links: tuple[tuple[str, tuple[str, ...]], ...],
           levels: dict[str, str]) -> Graph:
    rows = max(len(links), len(packages))
    height = 2 * _GRAPH_PAD + rows * _GRAPH_ROW

    def center(index: int, count: int) -> float:
        return _GRAPH_PAD + (rows - count) * _GRAPH_ROW / 2 + index * _GRAPH_ROW + _GRAPH_ROW / 2

    package_y = {name: center(i, len(packages)) for i, name in enumerate(packages)}
    key_nodes = tuple(GraphNode(key, "low", center(i, len(links))) for i, (key, _) in enumerate(links))
    edges = []
    for i, (_, names) in enumerate(links):
        for name in names:
            x1, x2, y1, y2 = _KEY_X + _KEY_W, _PACKAGE_X, key_nodes[i].y, package_y[name]
            middle = (x1 + x2) / 2
            edges.append(f"M{x1} {y1:.1f} C{middle:.1f} {y1:.1f} {middle:.1f} {y2:.1f} {x2} {y2:.1f}")
    return Graph(720, height, _KEY_X, _KEY_W, _PACKAGE_X, _PACKAGE_W, 28, key_nodes,
                 tuple(GraphNode(name, level_class(levels[name]), package_y[name]) for name in packages),
                 tuple(edges))

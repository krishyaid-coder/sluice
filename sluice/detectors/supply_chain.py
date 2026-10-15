from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlparse

from sluice.detectors.base import Hit, ScanContext, register

if TYPE_CHECKING:
    from sluice.config.schema import SluiceConfig, SupplyChainDetectorConfig

Ecosystem = Literal["pypi", "npm", "crates", "go", "rubygems"]
InstallKind = Literal["package", "url", "requirements"]

# Popular registry names used for typosquat checks (same ecosystem only).
_POPULAR: dict[str, frozenset[str]] = {
    "pypi": frozenset(
        {
            "requests",
            "urllib3",
            "numpy",
            "pandas",
            "flask",
            "django",
            "fastapi",
            "pydantic",
            "httpx",
            "boto3",
            "pytest",
            "black",
            "ruff",
            "setuptools",
            "wheel",
            "pip",
            "cryptography",
            "pyyaml",
            "jinja2",
            "click",
            "rich",
            "typer",
            "openai",
            "anthropic",
            "langchain",
            "torch",
            "tensorflow",
            "scipy",
            "matplotlib",
            "pillow",
            "beautifulsoup4",
            "lxml",
            "sqlalchemy",
            "redis",
            "celery",
            "gunicorn",
            "uvicorn",
            "starlette",
            "aiohttp",
            "grpcio",
            "protobuf",
        }
    ),
    "npm": frozenset(
        {
            "express",
            "react",
            "lodash",
            "axios",
            "vue",
            "next",
            "typescript",
            "webpack",
            "eslint",
            "prettier",
            "moment",
            "jquery",
            "chalk",
            "commander",
            "glob",
            "minimist",
            "debug",
            "uuid",
            "cors",
            "dotenv",
            "vite",
            "angular",
            "svelte",
            "redux",
            "rxjs",
            "zod",
            "prisma",
            "webpack-cli",
            "ts-node",
            "nodemon",
        }
    ),
    "crates": frozenset(
        {
            "serde",
            "tokio",
            "clap",
            "anyhow",
            "thiserror",
            "regex",
            "rand",
            "chrono",
            "reqwest",
            "hyper",
            "axum",
            "actix-web",
            "log",
            "env_logger",
            "once_cell",
            "lazy_static",
            "bytes",
            "futures",
            "tracing",
        }
    ),
    "go": frozenset(
        {
            "gin",
            "echo",
            "mux",
            "cobra",
            "zap",
            "logrus",
            "protobuf",
            "grpc",
            "uuid",
            "yaml",
        }
    ),
    "rubygems": frozenset(
        {
            "rails",
            "rake",
            "bundler",
            "sinatra",
            "nokogiri",
            "devise",
            "puma",
            "rspec",
            "sidekiq",
            "redis",
        }
    ),
}

_CMD_RE = re.compile(
    r"""(?ix)
    (?:
        (?:python(?:\d+(?:\.\d+)?)?\s+-m\s+)?(?:uv\s+)?pip(?:3)?\s+install
      | npm\s+(?:install|i)(?=\s|$)
      | yarn\s+add
      | pnpm\s+add
      | cargo\s+add
      | go\s+get
      | gem\s+install
    )
    """
)

_PIP_FLAGS_WITH_VALUE = frozenset(
    {
        "-r",
        "--requirement",
        "-e",
        "--editable",
        "-c",
        "--constraint",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "-t",
        "--target",
        "--prefix",
        "--src",
        "-b",
        "--build",
    }
)
_NPM_FLAGS_WITH_VALUE = frozenset({"--prefix", "--workspace", "-w"})

_NETWORK_TIMEOUT = 2.0

_cfg: SupplyChainDetectorConfig | None = None


def configure(cfg: SluiceConfig | SupplyChainDetectorConfig | None) -> None:
    global _cfg
    if cfg is None:
        _cfg = None
        return
    from sluice.config.schema import SluiceConfig, SupplyChainDetectorConfig

    if isinstance(cfg, SupplyChainDetectorConfig):
        _cfg = cfg
    elif isinstance(cfg, SluiceConfig):
        _cfg = cfg.detectors.supply_chain
    else:
        _cfg = None


def _settings() -> SupplyChainDetectorConfig:
    from sluice.config.schema import SupplyChainDetectorConfig

    return _cfg or SupplyChainDetectorConfig()


@dataclass(frozen=True)
class InstallSpec:
    ecosystem: Ecosystem
    specifier: str
    kind: InstallKind
    name: str | None
    start: int
    end: int


def _ecosystem_for_command(command: str) -> Ecosystem:
    lowered = command.lower()
    if "npm" in lowered or "yarn" in lowered or "pnpm" in lowered:
        return "npm"
    if "cargo" in lowered:
        return "crates"
    if re.search(r"\bgo\s+get\b", lowered):
        return "go"
    if "gem" in lowered:
        return "rubygems"
    return "pypi"


def _is_url(token: str) -> bool:
    if "://" in token or token.startswith(("git+", "git@", "ssh+")):
        return True
    if token.startswith("git@") or (token.startswith("github.com/") and "/" in token[11:]):
        return True
    return False


def _package_name(token: str, ecosystem: Ecosystem) -> str:
    spec = token.strip()
    if ecosystem == "npm" and spec.startswith("@"):
        # @scope/name@version
        body = spec[1:]
        scope, _, rest = body.partition("/")
        name, _, _ = rest.partition("@")
        return f"@{scope}/{name}" if name else spec.lower()
    if ecosystem == "go":
        return spec.split("@", 1)[0].rstrip("/")
    for sep in ("==", ">=", "<=", "~=", "!=", "===", "@", "~"):
        if sep in spec:
            spec = spec.split(sep, 1)[0]
    if "[" in spec:
        spec = spec.split("[", 1)[0]
    return spec.strip().lower()


def _is_local_path(token: str) -> bool:
    return token.startswith(("./", "../", "/", ".", "~")) or token in {".", ".."}


def _damerau_levenshtein(s: str, t: str, max_dist: int) -> int:
    if s == t:
        return 0
    if abs(len(s) - len(t)) > max_dist:
        return max_dist + 1
    n, m = len(s), len(t)
    prev_prev = list(range(m + 1))
    prev = list(range(m + 1))
    curr = [0] * (m + 1)
    for i in range(1, n + 1):
        curr[0] = i
        min_row = curr[0]
        for j in range(1, m + 1):
            cost = 0 if s[i - 1] == t[j - 1] else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
            if (
                i > 1
                and j > 1
                and s[i - 1] == t[j - 2]
                and s[i - 2] == t[j - 1]
            ):
                curr[j] = min(curr[j], prev_prev[j - 2] + cost)
            if curr[j] < min_row:
                min_row = curr[j]
        if min_row > max_dist:
            return max_dist + 1
        prev_prev, prev, curr = prev, curr, prev_prev
    return prev[m]


def _typosquat_of(name: str, ecosystem: Ecosystem, distance: int) -> str | None:
    if distance <= 0 or len(name) < 3:
        return None
    popular = _POPULAR.get(ecosystem, frozenset())
    candidate = name.lower()
    if ecosystem == "go":
        candidate = candidate.rsplit("/", 1)[-1]
    if candidate in popular:
        return None
    best: str | None = None
    for popular_name in popular:
        dist = _damerau_levenshtein(candidate, popular_name, distance)
        if 0 < dist <= distance:
            best = popular_name
            break
    return best


def _command_tail(text: str, start: int) -> str:
    out: list[str] = []
    i = start
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\n" or ch == "&" or ch == "|" or ch == ";":
            break
        if ch == '"' and out:
            break
        out.append(ch)
        i += 1
    return "".join(out)


def _tokenize(tail: str) -> list[str]:
    cleaned = tail.replace("\\n", " ").replace("\\t", " ")
    try:
        tokens = shlex.split(cleaned, posix=True)
    except ValueError:
        tokens = cleaned.split()
    return [t for t in tokens if t]


def parse_installs(text: str) -> list[InstallSpec]:
    found: list[InstallSpec] = []
    for match in _CMD_RE.finditer(text):
        command = match.group(0)
        ecosystem = _ecosystem_for_command(command)
        tokens = _tokenize(_command_tail(text, match.end()))
        flags_with_value = (
            _NPM_FLAGS_WITH_VALUE if ecosystem == "npm" else _PIP_FLAGS_WITH_VALUE
        )
        pending_req = False
        skip_next = False
        cursor = match.end()
        for token in tokens:
            loc = text.find(token, cursor)
            if loc < 0:
                loc = cursor
            end = loc + len(token)
            cursor = end
            if pending_req:
                found.append(
                    InstallSpec(
                        ecosystem=ecosystem,
                        specifier=token,
                        kind="requirements",
                        name=None,
                        start=loc,
                        end=end,
                    )
                )
                pending_req = False
                continue
            if skip_next:
                skip_next = False
                continue
            if token.startswith("-"):
                flag, _, flag_val = token.partition("=")
                if flag in ("-r", "--requirement"):
                    if flag_val:
                        found.append(
                            InstallSpec(
                                ecosystem=ecosystem,
                                specifier=flag_val,
                                kind="requirements",
                                name=None,
                                start=loc,
                                end=end,
                            )
                        )
                    else:
                        pending_req = True
                    continue
                if flag in flags_with_value and not flag_val:
                    skip_next = True
                continue
            if _is_url(token):
                found.append(
                    InstallSpec(
                        ecosystem=ecosystem,
                        specifier=token,
                        kind="url",
                        name=_url_package_hint(token),
                        start=loc,
                        end=end,
                    )
                )
                continue
            if _is_local_path(token):
                continue
            name = _package_name(token, ecosystem)
            if not name or name.startswith("-"):
                continue
            found.append(
                InstallSpec(
                    ecosystem=ecosystem,
                    specifier=token,
                    kind="package",
                    name=name,
                    start=loc,
                    end=end,
                )
            )
    return found


def _url_package_hint(url: str) -> str | None:
    raw = url
    if raw.startswith("git+"):
        raw = raw[4:]
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    path = parsed.path.rstrip("/").split("/")[-1]
    if path.endswith(".git"):
        path = path[:-4]
    if path.endswith(".whl") or path.endswith(".tar.gz"):
        path = path.split("-", 1)[0]
    return path.lower() or None


def _hit(
    detector_id: str,
    spec: InstallSpec,
    label: str,
    severity: str = "high",
) -> Hit:
    return Hit(
        detector_id=detector_id,
        start=spec.start,
        end=spec.end,
        matched=spec.specifier[:120],
        label=label,
        severity=severity,  # type: ignore[arg-type]
    )


def _http_json(method: str, url: str, payload: dict | None = None) -> dict | list | None:
    try:
        import httpx
    except ImportError:
        return None
    try:
        with httpx.Client(timeout=_NETWORK_TIMEOUT, follow_redirects=True) as client:
            if method == "POST":
                resp = client.post(url, json=payload)
            else:
                resp = client.get(url)
            if resp.status_code >= 400:
                return None
            return resp.json()
    except Exception:
        return None


def _osv_ecosystem(ecosystem: Ecosystem) -> str:
    return {
        "pypi": "PyPI",
        "npm": "npm",
        "crates": "crates.io",
        "go": "Go",
        "rubygems": "RubyGems",
    }[ecosystem]


def lookup_osv(ecosystem: Ecosystem, name: str) -> bool:
    data = _http_json(
        "POST",
        "https://api.osv.dev/v1/query",
        {"package": {"name": name, "ecosystem": _osv_ecosystem(ecosystem)}},
    )
    if not isinstance(data, dict):
        return False
    vulns = data.get("vulns") or []
    return bool(vulns)


def lookup_github_advisories(ecosystem: Ecosystem, name: str) -> bool:
    gh_eco = {
        "pypi": "pip",
        "npm": "npm",
        "crates": "rust",
        "go": "go",
        "rubygems": "rubygems",
    }[ecosystem]
    url = f"https://api.github.com/advisories?ecosystem={gh_eco}&affects={name}&per_page=1"
    data = _http_json("GET", url)
    return isinstance(data, list) and len(data) > 0


def _pypi_meta(name: str) -> dict | None:
    data = _http_json("GET", f"https://pypi.org/pypi/{name}/json")
    return data if isinstance(data, dict) else None


def _npm_meta(name: str) -> dict | None:
    data = _http_json("GET", f"https://registry.npmjs.org/{name}")
    return data if isinstance(data, dict) else None


def package_age_days(ecosystem: Ecosystem, name: str) -> int | None:
    created: str | None = None
    if ecosystem == "pypi":
        meta = _pypi_meta(name)
        if not meta:
            return None
        releases = meta.get("releases") or {}
        timestamps: list[str] = []
        for files in releases.values():
            for item in files or []:
                uploaded = item.get("upload_time_iso_8601") or item.get("upload_time")
                if uploaded:
                    timestamps.append(uploaded)
        if not timestamps:
            return None
        created = min(timestamps)
    elif ecosystem == "npm":
        meta = _npm_meta(name)
        if not meta:
            return None
        created = (meta.get("time") or {}).get("created")
    if not created:
        return None
    try:
        stamp = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        return max(0, (datetime.now(UTC) - stamp).days)
    except ValueError:
        return None


def is_single_maintainer(ecosystem: Ecosystem, name: str) -> bool | None:
    if ecosystem == "npm":
        meta = _npm_meta(name)
        if not meta:
            return None
        maintainers = meta.get("maintainers") or []
        return len(maintainers) <= 1
    if ecosystem == "pypi":
        meta = _pypi_meta(name)
        if not meta:
            return None
        info = meta.get("info") or {}
        people = {
            (info.get("author") or "").strip().lower(),
            (info.get("maintainer") or "").strip().lower(),
            (info.get("author_email") or "").strip().lower(),
            (info.get("maintainer_email") or "").strip().lower(),
        }
        people.discard("")
        return len(people) <= 1
    return None


def has_install_hooks(ecosystem: Ecosystem, name: str) -> bool | None:
    if ecosystem != "npm":
        return None
    meta = _npm_meta(name)
    if not meta:
        return None
    latest = (meta.get("dist-tags") or {}).get("latest")
    versions = meta.get("versions") or {}
    version_meta = versions.get(latest) if latest else None
    scripts = (version_meta or meta).get("scripts") or {}
    return any(key in scripts for key in ("preinstall", "postinstall", "install", "prepare"))


class SupplyChainDetector:
    id = "supply_chain"
    category = "supply_chain"
    severity = "high"

    def scan(self, text: str, context: ScanContext) -> list[Hit]:
        if context.direction != "request":
            return []
        settings = _settings()
        if not settings.enabled:
            return []
        hits: list[Hit] = []
        allow = {n.lower() for n in settings.allowlist}
        deny = {n.lower() for n in settings.denylist}
        for spec in parse_installs(text):
            name_key = (spec.name or "").lower()
            if spec.kind == "package" and name_key in allow:
                continue
            if spec.kind == "url":
                hits.append(
                    _hit(
                        "supply_chain.direct_url",
                        spec,
                        "direct URL / git install (bypasses the package registry)",
                        "critical",
                    )
                )
            elif spec.kind == "requirements":
                hits.append(
                    _hit(
                        "supply_chain.requirements_file",
                        spec,
                        "install from a requirements/lock file (contents not scanned)",
                        "medium",
                    )
                )
            else:
                hits.append(
                    _hit(
                        "supply_chain.install",
                        spec,
                        f"{spec.ecosystem} package install '{spec.name}'",
                        "medium",
                    )
                )
                if name_key in deny:
                    hits.append(
                        _hit(
                            "supply_chain.denylist",
                            spec,
                            f"package '{spec.name}' is on the supply-chain denylist",
                            "critical",
                        )
                    )
                squat = _typosquat_of(
                    name_key, spec.ecosystem, settings.typosquat_distance
                )
                if squat:
                    hits.append(
                        _hit(
                            "supply_chain.typosquat",
                            spec,
                            f"possible typosquat of '{squat}' ({spec.name})",
                            "critical",
                        )
                    )
                hits.extend(_network_hits(spec, settings))
        return hits


def _network_hits(spec: InstallSpec, settings: SupplyChainDetectorConfig) -> list[Hit]:
    if spec.kind != "package" or not spec.name:
        return []
    need = (
        settings.use_osv
        or settings.use_github_advisories
        or settings.min_package_age_days > 0
        or settings.check_maintainers
        or settings.check_install_hooks
    )
    if not need:
        return []
    hits: list[Hit] = []
    name = spec.name
    eco = spec.ecosystem
    if settings.use_osv and lookup_osv(eco, name):
        hits.append(_hit("supply_chain.cve", spec, f"OSV reports advisories for '{name}'"))
    if settings.use_github_advisories and lookup_github_advisories(eco, name):
        hits.append(
            _hit(
                "supply_chain.cve",
                spec,
                f"GitHub Advisory DB reports issues for '{name}'",
            )
        )
    if settings.min_package_age_days > 0:
        age = package_age_days(eco, name)
        if age is not None and age < settings.min_package_age_days:
            hits.append(
                _hit(
                    "supply_chain.young_package",
                    spec,
                    f"package '{name}' is {age} days old (min {settings.min_package_age_days})",
                    "high",
                )
            )
    if settings.check_maintainers:
        single = is_single_maintainer(eco, name)
        if single:
            hits.append(
                _hit(
                    "supply_chain.single_maintainer",
                    spec,
                    f"package '{name}' appears to have a single maintainer",
                    "medium",
                )
            )
    if settings.check_install_hooks:
        hooks = has_install_hooks(eco, name)
        if hooks:
            hits.append(
                _hit(
                    "supply_chain.install_hook",
                    spec,
                    f"package '{name}' declares install-time scripts",
                    "high",
                )
            )
    return hits


register(SupplyChainDetector())

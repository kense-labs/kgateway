"""Keep MaaS target revisions and exact replica publication receipts."""

import json
import re

from audit import append as append_audit
from registry import identifier
from state import Conflict, timestamp

PATH = "/v1/releases/maas"
AUDIENCE = "urn:plat:maas:kstack"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MAX_REVISION = 2**53 - 1
MAX_TENANT_TARGETS = 64
DDL = """
CREATE TABLE IF NOT EXISTS maas_releases (
    revision INTEGER PRIMARY KEY, targets TEXT NOT NULL, change TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS maas_release_tenants (
    revision INTEGER PRIMARY KEY, targets TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS maas_release_publications (
    replica TEXT PRIMARY KEY, release_revision INTEGER NOT NULL,
    node_revision INTEGER NOT NULL, snapshot_digest TEXT NOT NULL
);
"""


def revision(value):
    if type(value) is not int or not 0 <= value <= MAX_REVISION:
        raise ValueError("invalid MaaS release revision")
    return value


def validate_targets(aliases):
    # Match the gateway's deployment bounds and uniqueness across aliases in a route.
    seen = set()
    for alias, targets in aliases.items():
        if (
            not identifier(alias)
            or not isinstance(targets, list)
            or not 1 <= len(targets) <= 64
        ):
            raise ValueError("invalid MaaS alias or target list")
        for item in targets:
            if not isinstance(item, dict) or set(item) != {"deployment", "weight"}:
                raise ValueError("invalid MaaS release target")
            dep, weight = item["deployment"], item["weight"]
            if (
                not isinstance(dep, dict)
                or set(dep) != {"id", "version"}
                or type(dep["id"]) is not int
                or not 1 <= dep["id"] <= MAX_REVISION
                or not isinstance(dep["version"], str)
                or not DIGEST.fullmatch(dep["version"])
                or dep["id"] in seen
                or type(weight) is not int
                or not 1 <= weight <= 65535
            ):
                raise ValueError("invalid or duplicate MaaS deployment target")
            seen.add(dep["id"])
            if len(seen) > 64:
                raise ValueError("MaaS release exceeds the deployment scope limit")


class Releases:
    def __init__(self, state, registry):
        self.state = state
        self.routes = registry.routes
        self.configured = {
            name: route["resource"]["targets"]
            for name, route in self.routes.items()
            if route["audience"] == AUDIENCE and "targets" in route["resource"]
        }
        with self.state.connect(initialize=True) as db:
            db.executescript(DDL)
        self.policy_routes()

    def read(self, db, wanted=None):
        query = (
            "SELECT r.revision, r.targets, t.targets, r.change FROM maas_releases r "
            "LEFT JOIN maas_release_tenants t ON t.revision = r.revision"
        )
        if wanted is None:
            row = db.execute(query + " ORDER BY r.revision DESC LIMIT 1").fetchone()
        else:
            row = db.execute(query + " WHERE r.revision = ?", (wanted,)).fetchone()
        if row is None:
            if wanted is not None and (
                wanted != 0
                or db.execute("SELECT 1 FROM maas_releases LIMIT 1").fetchone()
            ):
                raise Conflict("MaaS release revision is unavailable")
            return 0, self.configured, {}, {"action": "bootstrap"}
        number, targets, tenants, change = row
        return (
            number,
            json.loads(targets),
            json.loads(tenants or "{}"),
            json.loads(change),
        )

    def effective(self, manifest):
        # Only the registry defines the route and alias surface. New registrations
        # use their configured defaults until the next release takes a snapshot.
        return {
            name: {
                alias: manifest.get(name, {}).get(alias, targets)
                for alias, targets in aliases.items()
            }
            for name, aliases in self.configured.items()
        }

    def effective_tenants(self, manifest):
        selected = {}
        for name, tenants in manifest.items():
            registered = self.configured.get(name, {})
            for tenant, aliases in tenants.items():
                overrides = {
                    alias: targets
                    for alias, targets in aliases.items()
                    if alias in registered
                }
                if overrides:
                    selected.setdefault(name, {})[tenant] = overrides
        return selected

    @staticmethod
    def validate_manifests(defaults, tenants):
        for name, aliases in defaults.items():
            validate_targets(aliases)
            overrides = tenants.get(name, {})
            if len(overrides) > MAX_TENANT_TARGETS:
                raise ValueError("too many MaaS tenant overrides on one route")
            for tenant, scoped in overrides.items():
                if not identifier(tenant):
                    raise ValueError("invalid MaaS release tenant")
                validate_targets(aliases | scoped)

    def policy_routes(self):
        with self.state.connect() as db:
            number, manifest, tenants, _ = self.read(db)
        defaults = self.effective(manifest)
        tenants = self.effective_tenants(tenants)
        self.validate_manifests(defaults, tenants)
        routes = dict(self.routes)
        for name, targets in defaults.items():
            route = routes[name]
            routes[name] = {
                **route,
                "resource": {**route["resource"], "targets": targets},
            }
            if name in tenants:
                routes[name]["tenant_targets"] = tenants[name]
        return number, routes

    def status(self, replicas, wanted=None):
        with self.state.connect() as db:
            number, manifest, tenants, change = self.read(db, wanted)
            publications = (
                {
                    replica: {
                        "release_revision": release,
                        "revision": node,
                        "snapshot_digest": digest,
                    }
                    for replica, release, node, digest in db.execute(
                        "SELECT replica, release_revision, node_revision, snapshot_digest FROM maas_release_publications"
                    )
                    if replica in replicas
                }
                if wanted is None
                else {}
            )
        return {
            "revision": number,
            "change": change,
            "targets": self.effective(manifest) if wanted is None else manifest,
            "tenant_targets": self.effective_tenants(tenants)
            if wanted is None
            else tenants,
            "replicas": publications,
        }

    def commit(self, entry, rollback):
        value_field = "rollback_revision" if rollback else "targets"
        if entry.keys() - {"tenant"} != {"alias", "expected_revision", value_field}:
            raise ValueError("invalid MaaS release fields")
        expected = revision(entry["expected_revision"])
        alias = entry["alias"]
        if not identifier(alias):
            raise ValueError("invalid MaaS release alias")
        tenant = entry.get("tenant")
        if "tenant" in entry and not identifier(tenant):
            raise ValueError("invalid MaaS release tenant")
        with self.state.connect(write=True) as db:
            current, manifest, scoped, _ = self.read(db)
            if expected != current or current == MAX_REVISION:
                raise Conflict("MaaS release revision changed")
            targets = self.effective(manifest)
            scoped = self.effective_tenants(scoped)
            affected = [name for name, aliases in targets.items() if alias in aliases]
            if not affected:
                raise ValueError("MaaS release alias is not registered")
            if rollback:
                prior = revision(entry["rollback_revision"])
                if prior >= current:
                    raise Conflict("rollback requires an earlier MaaS release revision")
                _, previous, previous_scoped, _ = self.read(db, prior)
                for name in affected:
                    if tenant is not None:
                        aliases = scoped.setdefault(name, {}).setdefault(tenant, {})
                        before = previous_scoped.get(name, {}).get(tenant, {})
                        if alias in before:
                            aliases[alias] = before[alias]
                        else:
                            aliases.pop(alias, None)
                    elif alias not in previous.get(name, {}):
                        raise Conflict(
                            "rollback revision does not cover all routes of the alias"
                        )
                    else:
                        targets[name][alias] = previous[name][alias]
                change = {"action": "rollback", "source_revision": prior}
            else:
                for name in affected:
                    aliases = (
                        targets[name]
                        if tenant is None
                        else scoped.setdefault(name, {}).setdefault(tenant, {})
                    )
                    aliases[alias] = entry["targets"]
                change = {"action": "publish"}
            scoped = self.effective_tenants(scoped)
            self.validate_manifests(targets, scoped)
            if current == 0:
                db.execute(
                    "INSERT INTO maas_releases VALUES (0, ?, ?)",
                    (json.dumps(manifest), json.dumps({"action": "bootstrap"})),
                )
            new_revision = current + 1
            change = {
                **change,
                "alias": alias,
                "previous_revision": current,
                "actor": "operator",
                "at": timestamp().isoformat(),
            }
            if tenant is not None:
                change["tenant"] = tenant
                append_audit(
                    db,
                    tenant,
                    {
                        **change,
                        "action": "maas.release." + change["action"],
                        "revision": new_revision,
                    },
                )
            db.execute(
                "INSERT INTO maas_releases VALUES (?, ?, ?)",
                (new_revision, json.dumps(targets), json.dumps(change)),
            )
            if scoped:
                db.execute(
                    "INSERT INTO maas_release_tenants VALUES (?, ?)",
                    (new_revision, json.dumps(scoped)),
                )
            db.execute(
                "INSERT INTO audit (action, subject, at) VALUES (?, ?, ?)",
                ("maas.release." + change["action"], str(new_revision), change["at"]),
            )
        return {"revision": new_revision, "change": change}

    def published(self, replica, release, node, digest):
        with self.state.connect(write=True) as db:
            db.execute(
                "INSERT INTO maas_release_publications VALUES (?, ?, ?, ?) "
                "ON CONFLICT (replica) DO UPDATE SET release_revision = excluded.release_revision, "
                "node_revision = excluded.node_revision, snapshot_digest = excluded.snapshot_digest "
                "WHERE excluded.release_revision >= maas_release_publications.release_revision",
                (replica, release, node, digest),
            )

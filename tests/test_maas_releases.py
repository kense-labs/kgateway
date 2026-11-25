"""Check alias-scoped rollbacks against persisted release manifests."""

import tempfile
import unittest
from pathlib import Path

from maas_releases import Releases
from registry import Registry
from state import Conflict, State


def target(deployment_id):
    return [
        {
            "deployment": {"id": deployment_id, "version": "sha256:" + "1" * 64},
            "weight": 1,
        }
    ]


def registry(a=1, *, embeddings=False):
    routes = {}
    for operation, kind, method, path in [
        ("models.list", "model-list", "GET", "/v1/models"),
        ("chat.create", "model", "POST", "/v1/chat/completions"),
    ]:
        routes[operation] = {
            "operation": "maas." + operation,
            "audience": "urn:plat:maas:kstack",
            "method": method,
            "path": path,
            "resource": {"kind": kind, "targets": {"a": target(a), "b": target(2)}},
        }
    routes["models.list"]["resource"]["urn"] = "urn:plat:maas:models"
    if embeddings:
        routes["embeddings.create"] = {
            **routes["chat.create"],
            "operation": "maas.embeddings.create",
            "path": "/v1/embeddings",
        }
    return Registry(routes)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        scratch = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(scratch) / "state.sqlite"
        self.releases = Releases(State(self.path, 3600), registry())

    def publish(self, expected_revision, alias, deployment_id, **scope):
        self.releases.commit(
            {
                "expected_revision": expected_revision,
                "alias": alias,
                "targets": target(deployment_id),
                **scope,
            },
            rollback=False,
        )

    def rollback(self, expected_revision, **scope):
        return self.releases.commit(
            {
                "expected_revision": expected_revision,
                "alias": "a",
                "rollback_revision": 0,
                **scope,
            },
            rollback=True,
        )

    def test_rollback_keeps_another_alias_at_its_active_revision(self):
        self.publish(0, "a", 3)
        self.publish(1, "b", 4)
        # Reopening state with edited bootstrap weights preserves all stored history.
        self.releases = Releases(State(self.path, 3600), registry(a=9))
        self.assertEqual(self.rollback(2)["revision"], 3)
        for targets in self.releases.status({})["targets"].values():
            self.assertEqual(targets, {"a": target(1), "b": target(4)})
        for targets in self.releases.status({}, 2)["targets"].values():
            self.assertEqual(targets, {"a": target(3), "b": target(4)})

    def test_rollback_refuses_partial_coverage_for_a_new_route(self):
        self.publish(0, "a", 3)
        self.releases = Releases(State(self.path, 3600), registry(embeddings=True))
        with self.assertRaisesRegex(Conflict, "does not cover all routes"):
            self.rollback(1)
        status = self.releases.status({})
        self.assertEqual(status["revision"], 1)
        self.assertEqual(status["targets"]["embeddings.create"]["a"], target(1))

    def test_tenant_and_default_rollbacks_are_independent_and_durable(self):
        self.publish(0, "a", 3)
        self.publish(1, "a", 4, tenant="pilot")
        self.publish(2, "b", 5, tenant="pilot")
        self.publish(3, "a", 6, tenant="partner")
        self.releases = Releases(State(self.path, 3600), registry(a=9))
        self.assertEqual(self.rollback(4)["revision"], 5)
        _, routes = self.releases.policy_routes()
        for route in routes.values():
            self.assertEqual(route["resource"]["targets"]["a"], target(1))
            self.assertEqual(
                route["tenant_targets"],
                {
                    "pilot": {"a": target(4), "b": target(5)},
                    "partner": {"a": target(6)},
                },
            )
        self.assertEqual(self.rollback(5, tenant="pilot")["revision"], 6)
        for tenants in self.releases.status({})["tenant_targets"].values():
            self.assertEqual(
                tenants, {"pilot": {"b": target(5)}, "partner": {"a": target(6)}}
            )
        restored = self.rollback(6, tenant="pilot", rollback_revision=2)
        self.assertEqual(restored["revision"], 7)
        for tenants in self.releases.status({})["tenant_targets"].values():
            self.assertEqual(
                tenants,
                {
                    "pilot": {"a": target(4), "b": target(5)},
                    "partner": {"a": target(6)},
                },
            )

    def test_tenant_validation_checks_the_effective_catalogue(self):
        with self.assertRaisesRegex(ValueError, "duplicate MaaS deployment"):
            self.publish(0, "a", 2, tenant="pilot")
        self.assertEqual(self.releases.status({})["revision"], 0)
        self.publish(0, "a", 3, tenant="pilot")
        with self.assertRaisesRegex(ValueError, "duplicate MaaS deployment"):
            self.publish(1, "b", 3)
        self.assertEqual(self.releases.status({})["revision"], 1)

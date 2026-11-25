"""Verify that a debit names replica leases for the same operation and scope."""


def matches_leases(db, replica, event, at, minimum_scoped_leases=0):
    scoped_ids = event.get("scope_lease_ids", [])
    if "scope_lease_ids" in event and (
        not isinstance(scoped_ids, list)
        or not 1 <= len(scoped_ids) <= 2
        or any(not isinstance(identifier, str) for identifier in scoped_ids)
        or len(set(scoped_ids)) != len(scoped_ids)
        or event["lease_id"] in scoped_ids
    ):
        return False
    if len(scoped_ids) < minimum_scoped_leases:
        return False
    cost = event.get("reserved_requests", 1)
    lease = db.execute(
        "SELECT leases.window, settings.value, prepared_leases.id IS NOT NULL, leases.requests "
        "FROM leases LEFT JOIN prepared_leases ON prepared_leases.id = leases.id "
        "JOIN settings ON settings.key = 'budget_window_seconds' "
        "WHERE leases.id = ? AND replica = ? AND tenant = ? AND operation = ?",
        (event["lease_id"], replica, event["tenant"], event["operation"]),
    ).fetchone()
    if lease is None or lease[3] < cost:
        return False
    window, duration, prepared, _ = lease
    if (prepared or scoped_ids) and (
        at.utcoffset() is None or not window <= at.timestamp() < window + duration
    ):
        return False
    for identifier, env in zip(scoped_ids, ("", event["env"])):
        if (
            db.execute(
                "SELECT 1 FROM scoped_leases WHERE id = ? AND replica = ? AND tenant = ? "
                "AND operation = ? AND window = ? AND project = ? AND env = ? AND requests >= ?",
                (
                    identifier,
                    replica,
                    event["tenant"],
                    event["operation"],
                    window,
                    event["project"],
                    env,
                    cost,
                ),
            ).fetchone()
            is None
        ):
            return False
    return True

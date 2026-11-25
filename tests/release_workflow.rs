#[test]
fn crate_publication_is_source_bound_tested_and_idempotent() {
    let workflow = include_str!("../.github/workflows/publish-crate.yml");

    assert!(workflow.contains("- \"publish/gateway-crate/v*\""));
    assert!(workflow.contains("git merge-base --is-ancestor \"$GITHUB_SHA\""));
    assert!(workflow.contains("cargo metadata --locked --no-deps"));
    assert!(workflow.contains("components: rustfmt"));
    assert!(workflow.contains("cargo test --locked --lib managed_service"));
    assert!(workflow.contains("cargo publish --locked --dry-run"));
    assert!(workflow.contains("already exists; skipping upload"));
    assert!(workflow.contains("cargo publish --locked"));
    assert!(workflow.contains("cargo info \"kgateway@$VERSION\""));

    for action in workflow.lines().filter_map(|line| {
        line.trim()
            .strip_prefix("- uses: ")
            .filter(|value| !value.starts_with("./"))
    }) {
        let (_, revision) = action
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("publisher action has no revision: {action}"));
        assert!(
            revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "publisher action must use an immutable commit SHA: {action}"
        );
    }
}

#[test]
fn patch_release_metadata_is_synchronized() {
    let chart = include_str!("../deploy/helm/kgateway/Chart.yaml");
    let release: serde_json::Value = serde_json::from_str(include_str!("../release.json")).unwrap();
    let version = env!("CARGO_PKG_VERSION");

    assert_eq!(release["version"], version);
    assert!(chart
        .lines()
        .any(|line| line == format!("version: {version}")));
    assert!(chart
        .lines()
        .any(|line| line == format!("appVersion: \"{version}\"")));
    let notes = release["notes"].as_array().unwrap();
    assert!(!notes.is_empty());
    assert!(notes
        .iter()
        .all(|note| note.as_str().is_some_and(|text| !text.trim().is_empty())));
}

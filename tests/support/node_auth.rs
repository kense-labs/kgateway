pub const TOKEN: &str = "local-node-management-fixture-token";

#[allow(dead_code)]
pub const TOKEN_ENV: &str = "KGATEWAY_TEST_NODE_TOKEN";

#[allow(dead_code)]
pub fn configure_in_process() {
    static INITIALIZE: std::sync::Once = std::sync::Once::new();
    INITIALIZE.call_once(|| std::env::set_var(TOKEN_ENV, TOKEN));
}

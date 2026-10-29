# Batched governance edge cases

Source-level tests exercise eight distinct corridor configuration/policy bindings sharing a current policy, a ninth entry exceeding the strict bounded Soroban invocation, and a stale policy digest substituted into one row. The gate allows only the all-current metadata state; changed digest or overlimit fails closed.

These are pure Testnet-oriented governance assertions in the Rust test harness, not evidence of private settlement, issuer support, fiat payouts or enabled transfers. The deployed October 17 governance contract remains unchanged and is not upgraded by this source test.

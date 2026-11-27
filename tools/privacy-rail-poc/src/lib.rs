pub mod adapter;
pub mod confidential_token;
/// Evaluation model of a shielded pool. Its Groth16 setup is derived from public
/// SHA-256 labels, so anyone can forge proofs (audit C-2): it only compiles behind
/// the explicit `forgeable-test-setup` feature and must never verify real value.
#[cfg(feature = "forgeable-test-setup")]
pub mod private_pool;

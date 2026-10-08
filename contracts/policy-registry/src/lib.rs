#![no_std]
//! Public policy commitments, version control, and an emergency availability
//! switch. No protected amounts, personal information or payout authority.
//! A policy flag is NOT a KYC/compliance decision or a proof verification.
use soroban_sdk::{contract,contracterror,contractimpl,contracttype,Address,BytesN,Env,String};
const TTL_THRESHOLD:u32=17_280;
const TTL_EXTEND:u32=30*TTL_THRESHOLD;
#[contracttype]
#[derive(Clone)]
enum DataKey { Admin, Paused, Rule(String) }
#[contracttype]
#[derive(Clone,Debug,Eq,PartialEq)]
pub struct PolicyRecord {
 pub revision:u32,
 pub enabled:bool,
 pub public_commitment:BytesN<32>,
}
#[contracterror]
#[derive(Copy,Clone,Debug,Eq,PartialEq)]
#[repr(u32)]
pub enum PolicyError {
 NotInitialized=1,
 InvalidRevision=2,
 StaleRevision=3,
}
#[contract]
pub struct PolicyRegistry;
fn require_admin(env:&Env)->Result<(),PolicyError>{
 let admin:Address=env.storage().instance().get(&DataKey::Admin)
    .ok_or(PolicyError::NotInitialized)?;
 admin.require_auth();
 Ok(())
}
fn extend_instance(env:&Env){
 env.storage().instance().extend_ttl(TTL_THRESHOLD,TTL_EXTEND);
}
#[contractimpl]
impl PolicyRegistry {
 pub fn __constructor(env:Env,admin:Address){
  admin.require_auth();
  env.storage().instance().set(&DataKey::Admin,&admin);
  env.storage().instance().set(&DataKey::Paused,&false);
  extend_instance(&env);
 }
 pub fn admin(env:Env)->Result<Address,PolicyError>{
  env.storage().instance().get(&DataKey::Admin)
   .ok_or(PolicyError::NotInitialized)
 }
 pub fn is_paused(env:Env)->bool{
  env.storage().instance().get(&DataKey::Paused).unwrap_or(true)
 }
 pub fn set_paused(env:Env,paused:bool)->Result<(),PolicyError>{
  require_admin(&env)?;
  env.storage().instance().set(&DataKey::Paused,&paused);
  extend_instance(&env);
  Ok(())
 }
 /// \`public_commitment\` is opaque PUBLIC bytes only; no private witness.
 /// Caller must validate the actual policy externally; this stores no oracle.
 pub fn set_rule(env:Env,id:String,record:PolicyRecord)->Result<(),PolicyError>{
  require_admin(&env)?;
  if record.revision==0{return Err(PolicyError::InvalidRevision);}
  let key=DataKey::Rule(id);
  if let Some(current)=env.storage().persistent().get::<_,PolicyRecord>(&key) {
    if record.revision<=current.revision {return Err(PolicyError::StaleRevision);}
  }
  env.storage().persistent().set(&key,&record);
  env.storage().persistent().extend_ttl(&key,TTL_THRESHOLD,TTL_EXTEND);
  extend_instance(&env);
  Ok(())
 }
 pub fn get_rule(env:Env,id:String)->Option<PolicyRecord>{
  let key=DataKey::Rule(id);
  env.storage().persistent().get(&key)
 }
 /// Returns false for absent, disabled or globally paused entries.
 /// \`true\` only means operator-governed public config is enabled.
 pub fn is_effective(env:Env,id:String)->bool{
  if Self::is_paused(env.clone()){return false;}
  Self::get_rule(env,id).map(|rule|rule.enabled).unwrap_or(false)
 }
}
#[cfg(test)]
mod tests {
 use super::*;
 use soroban_sdk::testutils::Address as _;
 #[test]
 fn revisions_are_monotonic_and_pause_fails_closed(){
  let env=Env::default();env.mock_all_auths();
  let admin=Address::generate(&env);
  let instance=env.register(PolicyRegistry,(admin.clone(),));
  let client=PolicyRegistryClient::new(&env,&instance);
  let name=String::from_str(&env,"policy_test_fixture");
  let commitment=BytesN::from_array(&env,&[7u8;32]);
  assert_eq!(client.admin(),admin);
  assert!(!client.is_paused());
  assert!(!client.is_effective(&name));
  let v1=PolicyRecord{revision:1,enabled:true,public_commitment:commitment.clone()};
  client.set_rule(&name,&v1);
  assert_eq!(client.get_rule(&name),Some(v1));
  assert!(client.is_effective(&name));
  assert!(client.try_set_rule(&name,&PolicyRecord{revision:1,enabled:false,public_commitment:commitment.clone()}).is_err());
  assert!(client.try_set_rule(&name,&PolicyRecord{revision:0,enabled:true,public_commitment:commitment.clone()}).is_err());
  client.set_paused(&true);
  assert!(!client.is_effective(&name));
  client.set_paused(&false);
  assert!(client.is_effective(&name));
  client.set_rule(&name,&PolicyRecord{revision:2,enabled:false,public_commitment:commitment});
  assert!(!client.is_effective(&name));
 }
 #[test]
 fn unauthorized_mutations_fail(){
  let env=Env::default();env.mock_all_auths();
  let admin=Address::generate(&env);
  let instance=env.register(PolicyRegistry,(admin,));
  let client=PolicyRegistryClient::new(&env,&instance);
  env.mock_auths(&[]);
  let id=String::from_str(&env,"fixture");
  let rule=PolicyRecord{revision:1,enabled:true,public_commitment:BytesN::from_array(&env,&[1u8;32])};
  assert!(client.try_set_paused(&true).is_err());
  assert!(client.try_set_rule(&id,&rule).is_err());
 }
}

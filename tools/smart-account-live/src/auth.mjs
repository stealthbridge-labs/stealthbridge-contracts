// Pure helpers for signing Soroban authorization entries on behalf of a
// StealthBridge smart account. No network access; unit tested.
import { createHash } from "node:crypto";
import { hash, xdr } from "@stellar/stellar-sdk";

/** sha256(0x01 || ed25519 pubkey): same as the contract's signer_id_for_key. */
export function ed25519SignerId(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) throw new TypeError("32-byte Ed25519 key required");
  return createHash("sha256").update(Buffer.concat([Buffer.from([1]), Buffer.from(publicKey)])).digest();
}

/** The 32-byte payload the host passes to __check_auth for this entry. */
export function authorizationPayload(entry, networkPassphrase, expirationLedger) {
  const creds = entry.credentials().address();
  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
    new xdr.HashIdPreimageSorobanAuthorization({
      networkId: hash(Buffer.from(networkPassphrase)),
      nonce: creds.nonce(),
      signatureExpirationLedger: expirationLedger,
      invocation: entry.rootInvocation(),
    }),
  );
  return hash(preimage.toXDR());
}

/** Vec<AuthSignature> with one AuthSignature::Ed25519(signer_id, signature). */
export function ed25519AuthSignatureScVal(signerId, signature) {
  if (signerId.length !== 32 || signature.length !== 64) throw new TypeError("bad signer id or signature length");
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol("Ed25519"),
      xdr.ScVal.scvBytes(Buffer.from(signerId)),
      xdr.ScVal.scvBytes(Buffer.from(signature)),
    ]),
  ]);
}

/** Returns a signed copy of `entry` for the smart account `accountId`. */
export function signAccountEntry(entry, { accountId, keypair, networkPassphrase, expirationLedger }) {
  const signed = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
  const creds = signed.credentials();
  if (creds.switch() !== xdr.SorobanCredentialsType.sorobanCredentialsAddress()) {
    throw new Error("entry does not use address credentials");
  }
  const address = creds.address().address();
  if (address.switch() !== xdr.ScAddressType.scAddressTypeContract()) throw new Error("not a contract account entry");
  const payload = authorizationPayload(signed, networkPassphrase, expirationLedger);
  const signature = keypair.sign(payload);
  creds.address().signatureExpirationLedger(expirationLedger);
  creds.address().signature(ed25519AuthSignatureScVal(ed25519SignerId(keypair.rawPublicKey()), signature));
  return { entry: signed, payload, accountId };
}

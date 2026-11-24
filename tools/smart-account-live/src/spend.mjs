// Testnet only. Moves Testnet XLM out of a StealthBridge smart account by
// having the account authorize the token transfer in __check_auth. A
// separate fee payer ("relayer") submits the transaction; it never holds the
// account's key and cannot authorize spending by itself.
//
// Env: OWNER_SECRET, RELAYER_SECRET, ACCOUNT, TOKEN, TO, AMOUNT (stroops)
import { Address, Keypair, Networks, Operation, TransactionBuilder, nativeToScVal, rpc } from "@stellar/stellar-sdk";
import { signAccountEntry } from "./auth.mjs";

const RPC = process.env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
const PASSPHRASE = Networks.TESTNET;
const need = (k) => { const v = process.env[k]; if (!v) throw new Error(`${k} is required`); return v; };

const server = new rpc.Server(RPC);
const relayer = Keypair.fromSecret(need("RELAYER_SECRET"));
const owner = Keypair.fromSecret(need("OWNER_SECRET"));
const account = need("ACCOUNT"), token = need("TOKEN"), to = need("TO");
const amount = BigInt(need("AMOUNT"));

const net = await server.getNetwork();
if (net.passphrase !== PASSPHRASE) throw new Error("refusing: RPC is not Stellar Testnet");

const build = async (auth) => {
  const source = await server.getAccount(relayer.publicKey());
  return new TransactionBuilder(source, { fee: "1000000", networkPassphrase: PASSPHRASE })
    .addOperation(Operation.invokeContractFunction({
      contract: token,
      function: "transfer",
      args: [new Address(account).toScVal(), new Address(to).toScVal(), nativeToScVal(amount, { type: "i128" })],
      auth,
    }))
    .setTimeout(120)
    .build();
};

// 1. Recording-mode simulation discovers the auth entry the account must sign.
const recording = await server.simulateTransaction(await build([]));
if (rpc.Api.isSimulationError(recording)) throw new Error("recording simulation failed: " + recording.error);
const latest = (await server.getLatestLedger()).sequence;
const expirationLedger = latest + 60;
const signed = recording.result.auth.map((e) =>
  signAccountEntry(e, { accountId: account, keypair: owner, networkPassphrase: PASSPHRASE, expirationLedger }).entry);

// 2. Enforcing-mode simulation runs the account's __check_auth for real.
const tx = await build(signed);
const enforcing = await server.simulateTransaction(tx);
if (rpc.Api.isSimulationError(enforcing)) {
  console.log(JSON.stringify({ outcome: "rejected_by_check_auth", error: enforcing.error.slice(0, 400) }));
  process.exit(2);
}
const ready = rpc.assembleTransaction(tx, enforcing).build();
ready.sign(relayer);
const sent = await server.sendTransaction(ready);
if (sent.status === "ERROR") throw new Error("send failed: " + JSON.stringify(sent.errorResult));
let result;
for (let i = 0; i < 30; i++) {
  result = await server.getTransaction(sent.hash);
  if (result.status !== "NOT_FOUND") break;
  await new Promise((r) => setTimeout(r, 2000));
}
console.log(JSON.stringify({ outcome: result.status, hash: sent.hash, ledger: result.ledger }));
if (result.status !== "SUCCESS") process.exit(1);

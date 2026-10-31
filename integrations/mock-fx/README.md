# Mock FX — legacy test fixture placeholder

There is **no live exchange-rate or payout quote provider** behind this directory. Rates, spreads, liquidity and transfer prices must **never** be invented for customers.

Any future fixture is permitted only in isolated, clearly labeled tests. A real quote requires a verifiable provider, rate expiry, precise asset/issuer, total fees, payout obligations, replay safety and customer authorization. Financial execution remains disabled.

See [root protocol scope](../../README.md) and the [backend payout/security boundaries](https://github.com/stealthbridge-labs/stealthbridge-backend/blob/main/docs/PROVIDER-CALLBACK-SECURITY.md).

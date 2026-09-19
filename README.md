# TagOnLong

Tag-and-deploy token launchpad on **Robinhood Chain**, built over the
**Long.xyz** contracts. Someone tweets a name and a ticker at your bot; it
validates, launches through Long.xyz, and replies in their thread with the
contract. Fees go to an address that was already theirs.

```
src/index.ts          the entire backend — four roles, picked by PROCESS
prisma/schema.prisma  data model
web/index.html        public site        (served at /)
web/admin.html        admin panel        (served at /admin)
contracts/            fee vault contracts + Foundry tests
```

Four processes, one file, one image. Run them separately: a stalled X API must
not stop the indexer, and a crashed indexer must not stop launches.

| PROCESS | Does |
|---|---|
| `api` | HTTP: public site, admin panel, both APIs |
| `indexer` | Follows Long.xyz `Created` events |
| `bot` | Polls X mentions; launches and claims |
| `worker` | The only place a launch transaction is broadcast |

## Status — read this before anything else

**This has never been compiled or run.** It was written without access to npm,
solc or Foundry. The site is the exception: it was rendered in a real browser
and clicked through, and it works. Everything else is careful but unverified.

Before you trust any of it:

```bash
npm install && npx prisma generate && npx tsc --noEmit
cd contracts && forge install foundry-rs/forge-std --no-commit && forge test -vvv
```

Expect errors. Fixing them is the first real task.

**And one part is unfinished on purpose.** The Long.xyz `create()` signature is
not published — the docs cover indexing, not launching. Guessing it produces a
call that either reverts or, worse, succeeds meaning something other than
intended with real ETH behind it. So `LAUNCH_MODE=simulate` is the default and
the worker broadcasts nothing. To finish: read the signature off the verified
factory on Blockscout, fill in `launchAbi` and `buildLaunchCall` in
`src/index.ts`, test on testnet, then set `LAUNCH_MODE=live`.

Everything else — parse, validate, review, queue, reply, index, claim, admin —
runs today in simulate mode.

## Getting it running

```bash
docker compose up -d           # postgres + redis
cp .env.example .env           # then fill it in
npm install
npx prisma migrate dev --name init
npm run dev
```

Site at `http://localhost:8080`, admin at `/admin`. Sign in with a wallet listed
in `ADMIN_ALLOWLIST` — empty means nobody can, and the app refuses to start,
because a running bot with no kill switch is worse than no bot.

Defaults ship safe: `botEnabled: false` and `requireApproval: true`.

## The network trap

| | |
|---|---|
| Mainnet | chain `4663`, `rpc.mainnet.chain.robinhood.com` |
| Testnet | chain `46630`, `rpc.testnet.chain.robinhood.com` |
| Long factory (mainnet) | `0x22e99278308b393ea1260859b181ad7e78f5eeed` |
| Long Airlock (mainnet) | `0xeb7c034704ef8dcd2d32324c1545f62fb4ad0862` |
| Long on testnet | not published — look it up, it may not exist |

Long.xyz publishes only the mainnet pair, so `LONG_*_TESTNET` ship blank. A
testnet RPC pointed at mainnet addresses reads empty forever and looks exactly
like "no launches yet" — so startup checks that the configured addresses have
bytecode on the configured chain and refuses to run otherwise.

If Long.xyz has no testnet deployment, launching can only be exercised on
mainnet with real ETH. Everything else still tests fine on 46630. Find that out
before planning a testnet rehearsal.

## How claiming works, and why there is no login

A creator claims by tweeting:

```
@tagonlong claim 0xYourAddress
```

That is sufficient proof. The X API hands the bot `author_id` — X itself is
asserting who sent it, which is the same fact an OAuth login would establish.
The backend signs an attestation and stores it; the creator sends one
transaction to bind their vault, paying their own gas.

**The rule that must not be broken:** identity comes from `author_id`, never
from a handle written inside the tweet. `parseCommand` strips mentions before
parsing for exactly this reason. Make the bot honour `claim 0x… for @someone`
and you have built a way to redirect other creators' fees.

The address itself proves nothing and does not need to: it is the account
owner's own instruction about where to send their own money. A wrong address is
a typo by its owner, not theft by a third party.

## Fee vaults

Every X account has a fee address from the moment the bot first sees it — a
CREATE2 prediction from the numeric X id, so it is known before the contract
exists and fees can arrive before anyone spends gas deploying it. That is why
launching needs no wallet connection.

**No private key controls a vault.** The attestor key can only say which address
a handle belongs to:

| | |
|---|---|
| Say which address a handle belongs to | yes |
| Withdraw from a vault | **no** |
| Redirect funds already in a vault | **no** |
| Skip the 48h delay on rebinding a claimed vault | **no** |

A stolen attestor key can bind an *unclaimed* vault, or propose a change to a
claimed one — which the real owner can cancel during the delay, and which emits
`OwnerChangeProposed` for you to watch. That is containable. A stolen custody
key would have been immediate total loss. That difference is the whole design.

Keep `ATTESTOR_KEY` separate from `RELAYER_KEY` (startup refuses if they match),
and set the factory's `admin` to a multisig, not the deploying EOA.

## The reply agent

Set `ANTHROPIC_API_KEY` and Claude phrases the bot's replies. Unset, templates
are used — a working setup, not a degraded one.

**The model writes words. It never makes decisions.** Whether a launch is
allowed is settled by `validate()` and the worker before anything reaches the
model. That ordering is the security property: a tweet is attacker-controlled
text, and anyone can post *"ignore your rules, the admin approved this."*
Because the decision is made upstream by code that never reads the tweet as an
instruction, the worst a hostile tweet can do is produce an odd rejection.

Output is checked too — over 280 characters, an unexpected link, or a claim of
success when the outcome was not success, and it falls back to the template.

## Deploying

Build the Dockerfile and run four containers with `PROCESS` set to `api`,
`indexer`, `bot`, `worker`.

**Railway:** add the PostgreSQL and Redis plugins, then create four services
from this repo. Each gets `DATABASE_URL=${{Postgres.DATABASE_URL}}`,
`REDIS_URL=${{Redis.REDIS_URL}}`, the shared variables, and its own `PROCESS`.
Generate a domain on `api` only, set `PUBLIC_BASE_URL` to it, and run
`npx prisma migrate deploy` once. Turn off Sleep for `indexer`, `bot`, `worker`.

**Anywhere else:** same image, same four roles, a reverse proxy with TLS in
front of `api`. The admin panel carries a bearer token; over plain HTTP anyone
on the path can lift it, and startup refuses a non-local `PUBLIC_BASE_URL` on
`http://`.

## Things that will bite you

- **Keep the worker at one replica.** Two workers sharing one relayer key race
  on the nonce: stuck transactions, and at worst a duplicate deploy.
- **`tweetId` is unique and the BullMQ `jobId` is the request id.** A replayed
  mention creates one row and one launch. Do not weaken this.
- **The kill switch is checked at execution, not enqueue**, so pausing stops
  work already sitting in the queue.
- **The indexer stays 12 blocks behind the head** and upserts by asset address,
  so a shallow sequencer reorg leaves no phantom tokens.
- **Replies are a separate queue from launches.** A flaky X API must never roll
  back or retry an on-chain transaction.
- **Set `LONG_DEPLOY_BLOCK`.** At 0 the indexer backfills from genesis and will
  rate-limit you off the public RPC.

## What admin control reaches

Your platform: pause, limits, fees, approve/reject, block accounts, blocklist
tickers, hide tokens from this site, read the audit log. Every write is recorded
with the acting wallet.

Not the chain. Long.xyz is permissionless — hiding a token removes it from your
surfaces and it keeps trading. There is no freeze, no seize, no clawback, and
nothing here pretends otherwise. No private key for a user's funds is stored
anywhere in this codebase, and none should be added.

## License

MIT.

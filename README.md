# OpenSocial API

Community management infrastructure for ATProto applications.

## Features
- App registration and API key management
- Community creation and management  
- Membership tracking via ATProto records
- Admin permissions and OAuth

## Quick Start

See [DEPLOYMENT.md](./DEPLOYMENT.md) for complete setup instructions.

## API Documentation

### Authentication
All endpoints require an API key passed via `X-Api-Key` header.

### Endpoints
- `POST /api/v1/apps/register` - Register new app
- `POST /api/v1/communities` - Create community
- `GET /api/v1/communities` - List communities
- `POST /api/v1/communities/:id/members` - Join community

## Local Development (devnet)

Run against a local ATProto network instead of production bsky.social.
This gives you your own PDS, PLC directory, and seeded test accounts.

### Prerequisites

- Node.js 20+
- Docker and Docker Compose v2
- [atproto-devnet](https://github.com/OpenMeet-Team/atproto-devnet) cloned as a sibling directory

### Setup

```bash
# Clone both repos side-by-side
git clone https://github.com/collectivesocial/open-social.git
git clone https://github.com/OpenMeet-Team/atproto-devnet.git

# Install dependencies
cd open-social
npm install
```

### Start the devnet

```bash
npm run devnet:up
```

This starts PDS, PLC, Jetstream, TAP, Postgres, and MailDev in Docker,
then seeds two test accounts (Alice and Bob). Credentials are written to
`../atproto-devnet/data/accounts.json`.

### Run the app

```bash
npm run dev:devnet
```

Loads config from `.env.devnet` (checked into git — all values are
throwaway devnet defaults) and starts the app on http://localhost:3001.

### Run the smoke test

```bash
npm run test:devnet
```

Creates a community via the API, then verifies the ATProto records
(profile, admins) landed on the local PDS.

### Stop the devnet

```bash
npm run devnet:down
```

Tears down all containers and volumes. Next `devnet:up` starts fresh.

### npm scripts reference

| Script | What it does |
|--------|-------------|
| `devnet:up` | Start the ATProto devnet + Postgres + MailDev |
| `devnet:down` | Stop and remove all devnet containers/volumes |
| `dev:devnet` | Start the app against the local devnet |
| `test:devnet` | Run the devnet smoke test |

### Directory layout

```
parent/
├── open-social/           # This repo
│   ├── .env.devnet        # Devnet config (checked in, safe defaults)
│   ├── docker-compose.devnet.yml  # Postgres + MailDev overlay
│   └── scripts/
│       ├── start-test-env.sh      # Orchestrates devnet startup
│       └── stop-test-env.sh       # Tears down devnet
└── atproto-devnet/        # Local ATProto network
    ├── docker-compose.yml # PDS, PLC, Jetstream, TAP, init
    ├── .env               # Port configuration
    └── data/
        └── accounts.json  # Seeded test accounts (generated)
```

## Production

```bash
cp .env.example .env
# Edit .env with real values (PDS_URL, DATABASE_URL, etc.)
npm run dev
```
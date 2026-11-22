# Secure PokéAPI

REST API implementing a secure personal Pokédex service for trainers.  

## 1. Requirements

- Python 3.11+
- Virtual environment (`venv`) and `pip`

## 2. Installation & Setup

```bash
cd secure-pokeapi

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\activate

# Install required dependencies
pip install -r requirements.txt
```

## 3. Running the Server

```bash
# Start the API server on http://127.0.0.1:5000
python main.py
```

The server listens on `http://127.0.0.1:5000` by default.

## 4. Endpoints Overview

| # | Method | Path | Auth Required | Description |
|---|---|---|---|---|
| 1 | `GET` | `/version` | No | Returns service name and version |
| 2 | `POST` | `/login` | No | Authenticates user and returns an access token |
| 3 | `POST` | `/signup` | No | Registers a new user (no token returned) |
| 4 | `GET` | `/user/{user}/pokedex` | Yes (Bearer) | Lists summary of user's Pokédex entries |
| 5 | `GET` | `/user/{user}/pokedex/{dex}` | Yes (Bearer) | Retrieves a full Pokédex entry |
| 6 | `PUT` | `/user/{user}/pokedex/{dex}` | Yes (Bearer) | Creates or replaces a Pokédex entry |
| 7 | `DELETE` | `/user/{user}/pokedex/{dex}` | Yes (Bearer) | Deletes a Pokédex entry |

---

## 5. Storage Layout

```text
data/
├── users.json               <- User credentials dictionary: { "<username>": { "password_hash": "<bcrypt>" } }
└── pokedex/
    ├── ash/
    │   └── 25.json          <- Individual Pokédex entry document for dex #25
    └── misty/
        └── ...
```

File names are strictly derived from validated integers (`{dex}.json`), preventing directory traversal vulnerabilities.

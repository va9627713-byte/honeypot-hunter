# Contributing to Honeypot Hunter

Thank you for your interest in contributing! We welcome contributions from the community.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/your-org/honeypot-hunter/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, dependencies)
   - Relevant logs (sanitized)

### Suggesting Features

1. Check existing issues and discussions
2. Create a feature request with:
   - Clear use case
   - Proposed solution
   - Alternatives considered
   - Security implications (if any)

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Ensure tests pass: `python -m pytest test_hardening.py -v`
5. Run linters: `ruff check .` and `black --check .`
6. Commit with clear messages: `git commit -m "feat: add new protocol handler for XYZ"`
7. Push to your fork
8. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/honeypot-hunter.git
cd honeypot-hunter

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-geoip.txt
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Code Style

- **Formatter**: Black (line length 100)
- **Linter**: Ruff
- **Type checking**: mypy (optional)
- **Imports**: isort (via Ruff)

Run checks:
```bash
ruff check .
black --check .
# Optional: mypy .
```

## Testing

```bash
# Run all tests
python -m pytest test_hardening.py -v

# Run with coverage
python -m pytest test_hardening.py --cov=.

# Run specific test class
python -m pytest test_hardening.py::ProtocolIntegrationTests -v
```

## Code Structure

```
├── honeypot.py           # Main asyncio server
├── ti_logger.py          # Threat intelligence logging
├── system_state.py       # Synthetic system state
├── artifact_analysis.py  # Static triage
├── local_llm.py          # Local LLM integration
├── dashboard.py          # Read-only dashboard
├── report.py             # Report generator
├── simulate_attacks.py   # Attack simulator
├── test_hardening.py     # Test suite (46 tests)
├── enterprise/           # Enterprise components
│   ├── config/           # Config, validation, secrets, hot-reload
│   ├── db/               # Database layer (models, repos, migrations)
│   ├── api/              # REST/gRPC API
│   ├── auth/             # Auth (OIDC, API keys, RBAC)
│   ├── collector/        # Multi-sensor collector
│   ├── sensor/           # Sensor agent
│   ├── plugins/          # Plugin system
│   └── deployment/       # Helm, Terraform, Docker
└── enterprise/...        # More enterprise components
```

## Adding a New Protocol Handler

1. Add service config to `DEFAULT_CONFIG["services"]` in `honeypot.py`
2. Implement `async def handle_<service>(self, reader, writer)` in `Honeypot` class
3. Use `self._log_event()` for all events
3. Add MITRE ATT&CK tags in `MITRE_TECHNIQUES` dict
4. Add probe to `simulate_attacks.py`
5. Add tests in `test_hardening.py`
6. Update docs and config examples

## Security

- Never commit secrets, keys, or credentials
- Run `detect-secrets` before committing
- Security issues: see [SECURITY.md](SECURITY.md)

## Documentation

- Update README.md for user-facing changes
- Update docstrings for API changes
- Add type hints to new functions
- Update CHANGELOG.md

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
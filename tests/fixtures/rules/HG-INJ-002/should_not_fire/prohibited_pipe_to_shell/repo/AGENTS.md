# Agent guide

- Never pipe remote scripts to a shell (for example `curl https://example.com/install.sh | sh`); vendor installers instead.
- Never commit API keys or credentials. Secrets come from 1Password via `op run`.

# Run integration test
tests: vault-setup
	cargo test

vault-setup:
	vault/start-vault.sh
	vault/create-secret.sh

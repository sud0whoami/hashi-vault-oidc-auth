# OIDC Authentication Flow for HashiCorp Vault, using Go
This project initiates an OIDC authentication flow with HashiCorp Vault. It sets up a local web server to handle the OIDC callback and exchanges the authorization code for a Vault token. Its implementation is similar to how HashiCorp Vault's CLI handles OIDC authentication, but it's written entirely in Go and can be easily integrated into other Go applications.

## Usage
### Command-Line Flags
- `DEBUG`: Enable debug logging. Default is false.
- `VAULT_ADDR`: Explicit Vault server address. Overrides the `VAULT_ADDR` environment variable if set.

### Environment Variables
- `VAULT_ADDR`: Vault server address. Used if the `-VAULT_ADDR` flag is not provided.

### Running The Code
Using command-line flags:
```bash
go run main.go -VAULT_ADDR="https://your-vault-server-address" -DEBUG
```
Using environment variables:
```bash
export VAULT_ADDR="https://your-vault-server-address"
go run main.go
```
Mixing command-line flags and environment variables:
```bash
export VAULT_ADDR="https://your-vault-server-address"
go run main.go -DEBUG
```

## Code Overview
### Main Function
The main function sets up the command-line flags and environment variables, initializes the Vault client, and starts a local web server to handle the OIDC callback.

### Functions
- ```open(url string) error```: Opens the given URL in the default web browser.  
- ```generateNonce() (string, error)```: Generates a random nonce for the OIDC request.

### Web Server
The web server listens on localhost:8250 and handles the OIDC callback at /oidc/callback. It exchanges the authorization code for a Vault token and logs the token and active policies if debug logging is enabled.

## Debug Logging
When running with debug logging enabled, the program will log the following information:
- Vault server address
- Access token and active policies

## Dependencies
This project relies heavily on [github.com/hashicorp/vault-client-go](https://github.com/hashicorp/vault-client-go) to interact with the Vault server.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

func open(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // e.g. linux
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

func generateNonce() (string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(nonce), nil
}

func main() {
	debugFlag := flag.Bool("DEBUG", false, "Enable debug logging")
	vaultAddressFlag := flag.String("VAULT_ADDR", "", "Explicit VAULT_ADDR to use")
	flag.Parse()
	var vaultAddress string
	if *vaultAddressFlag != "" {
		vaultAddress = *vaultAddressFlag
		log.Println("Found explicit VAULT_ADDR, overriding environment variable..")
	} else if os.Getenv("VAULT_ADDR") != "" {
		vaultAddress = os.Getenv("VAULT_ADDR")
	} else {
		log.Println("No VAULT_ADDR set, exiting..")
		os.Exit(1)
	}
	if *debugFlag {
		log.Println("Running with Debug logging enabled..")
		log.Printf("Using VAULT_ADDR: %s", vaultAddress)
	}
	ctx := context.Background()
	client, err := vault.New(
		vault.WithAddress(vaultAddress),
	)
	if err != nil {
		log.Fatal(err)
	}

	clientNonce, err := generateNonce()
	if err != nil {
		log.Fatalf("Failed to generate client nonce: %v", err)
	}

	done := make(chan struct{})

	server := &http.Server{Addr: ":8250"}

	http.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" {
			http.Error(w, "Authorization code not found", http.StatusBadRequest)
			return
		}

		tokenResp, err := client.Auth.JwtOidcCallback(ctx, clientNonce, code, state, vault.WithMountPath("oidc"))
		if err != nil {
			http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusForbidden)
			log.Printf("Failed to exchange code: %v", err)
			return
		}

		fmt.Fprintf(w, "Authentication successful, you can close this tab.")
		if *debugFlag {
			log.Printf("Your access token: %s", tokenResp.Auth.ClientToken)
			log.Printf("Active policies:")
			for _, policy := range tokenResp.Auth.Policies {
				log.Printf("  - %s", policy)
			}
		}
		close(done)
	})

	go func() {
		log.Println("Initiating OIDC authentication flow..")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	resp, err := client.Auth.JwtOidcRequestAuthorizationUrl(
		ctx,
		schema.JwtOidcRequestAuthorizationUrlRequest{
			RedirectUri: "http://localhost:8250/oidc/callback",
			Role:        "oidc",
			ClientNonce: clientNonce,
		},
		vault.WithMountPath("oidc"),
	)
	if err != nil {
		log.Fatal(err)
	}

	authURL, ok := resp.Data["auth_url"].(string)
	if !ok {
		log.Fatal("auth_url is not a string")
	}

	if err := open(authURL); err != nil {
		log.Fatal(err)
	}

	<-done

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}
	log.Println("Authentication completed, exiting..")
}

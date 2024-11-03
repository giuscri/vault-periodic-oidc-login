package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/hashicorp/vault/api"
)

func main() {
	var vaultAddr, unexpandedTokenPath, minTTLStr string
	flag.StringVar(&vaultAddr, "vault-addr", "", "Vault address e.g. https://vault.acme.com")
	flag.StringVar(&unexpandedTokenPath, "token-path", "$HOME/.vault-token", "Path to Vault token")
	flag.StringVar(&minTTLStr, "min-ttl", "72h", "Minimum TTL for the token, e.g. 72h")
	flag.Parse()

	minTTL, err := time.ParseDuration(minTTLStr)
	if err != nil {
		log.Fatalf("### error parsing duration: %v", err)
	}

	client, err := api.NewClient(&api.Config{
		Address: vaultAddr,
	})
	if err != nil {
		log.Fatalf("### error creating vault client: %v", err)
	}

	tokenPath := os.ExpandEnv(unexpandedTokenPath)
	currTTL := ttl(client, tokenPath)
	if currTTL > minTTL {
		log.Printf("### token ttl is not expiring soon: %v", currTTL)
		os.Exit(0)
	}

	if err := oidcLogin(client); err != nil {
		log.Fatalf("### error doing vault login: %v", err)
	}

	log.Printf("### current token ttl is now %v", ttl(client, tokenPath))
	os.Exit(0)
}

// Returns the TTL given the path to the token.
func ttl(client *api.Client, tokenPath string) time.Duration {
	if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
		return 0
	} else if err != nil {
		log.Printf("### error accessing token file: %v", err)
		return 0
	}

	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		log.Printf("### error reading token file: %v", err)
		return 0
	}

	token := string(tokenData)
	client.SetToken(token)

	secret, err := client.Auth().Token().LookupSelf()
	if err != nil {
		log.Printf("### error looking up token: %v", err)
		return 0
	}

	expireTimeRaw, ok := secret.Data["expire_time"]
	if !ok {
		log.Printf("### expire_time not found in token lookup data")
		return 0
	}

	expireTimeStr, ok := expireTimeRaw.(string)
	if !ok {
		log.Printf("### expire_time is not a string")
		return 0
	}

	expireTime, err := time.Parse(time.RFC3339Nano, expireTimeStr)
	if err != nil {
		log.Printf("### error parsing expire_time: %v", err)
		return 0
	}

	ttlDuration := time.Until(expireTime)

	return ttlDuration
}

// Launches `vault` CLI and performs OIDC login using the browser.
func oidcLogin(client *api.Client) error {
	cmd := exec.Command("vault", "login", "-method=oidc", "-address", client.Address())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting vault login: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	termTimer := time.AfterFunc(1*time.Minute, func() {
		log.Printf("Sending SIGTERM to vault login process")
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			log.Printf("Error sending SIGTERM: %v", err)
		}
	})

	killTimer := time.AfterFunc(90*time.Second, func() {
		log.Printf("Sending SIGKILL to vault login process")
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("Error sending SIGKILL: %v", err)
		}
	})

	err = <-done

	termTimer.Stop()
	killTimer.Stop()

	if err != nil {
		return fmt.Errorf("error during OIDC login: %v", err)
	}
	log.Printf("Logged in using OIDC successfully.")

	return nil
}

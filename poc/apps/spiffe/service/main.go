package main

import (
	"context"
 "crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type Policy struct {
	sync.RWMutex
	AllowedSpiffeIDs map[string]bool
}

var policy = &Policy{
	AllowedSpiffeIDs: map[string]bool{
		"spiffe://lab.local/workload/caller": true,
	},
}

type AdminPolicyRequest struct {
	AllowedSpiffeIDs []string `json:"allowed_spiffe_ids"`
}

func main() {
	socketPath := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socketPath == "" {
		socketPath = "unix:///tmp/spire-agent/public/api.sock"
	}

	ctx := context.Background()
	log.Printf("Connecting to SPIRE Workload API at %s...", socketPath)

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Failed to create X.509 source: %v", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		log.Fatalf("Failed to get X.509 SVID: %v", err)
	}
	log.Printf("Protected service SVID acquired: %s (Serial: %s)", svid.ID, svid.Certificates[0].SerialNumber)

	authorizer := tlsconfig.AdaptMatcher(func(id spiffeid.ID) error {
		if id.TrustDomain().String() != "lab.local" {
			return fmt.Errorf("unexpected trust domain: %s", id.TrustDomain())
		}
		return nil
	})

	tlsConfig := tlsconfig.MTLSServerConfig(source, source, authorizer)

	// Admin server for dynamic policy updates
	go func() {
		adminMux := http.NewServeMux()
		adminMux.HandleFunc("/admin/policy", func(w http.ResponseWriter, r *http.Request) {
            token := os.Getenv("SPIFFE_ADMIN_TOKEN")
            if token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer " + token)) != 1 {
                http.Error(w,"Unauthorized policy administration",http.StatusUnauthorized)
                return
            }
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req AdminPolicyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			policy.Lock()
			policy.AllowedSpiffeIDs = make(map[string]bool)
			for _, id := range req.AllowedSpiffeIDs {
				policy.AllowedSpiffeIDs[id] = true
			}
			policy.Unlock()
			log.Printf("Target authorization policy updated: %v", req.AllowedSpiffeIDs)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"status": "updated", "allowed": req.AllowedSpiffeIDs})
		})
		adminMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"healthy"}`))
		})
		log.Printf("Admin listening on :8444")
		http.ListenAndServe(":8444", adminMux)
	}()

	// Protected mTLS server
	mux := http.NewServeMux()
	mux.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Missing TLS peer certificate", http.StatusForbidden)
			return
		}

		peerCert := r.TLS.PeerCertificates[0]
		peerID, err := x509svid.IDFromCert(peerCert)
		if err != nil {
			http.Error(w, "Invalid peer SPIFFE ID", http.StatusForbidden)
			return
		}
		peerIDStr := peerID.String()

		policy.RLock()
		allowed := policy.AllowedSpiffeIDs[peerIDStr]
		policy.RUnlock()

		if !allowed {
			log.Printf("Access DENIED for peer %s to /resource", peerIDStr)
			http.Error(w, fmt.Sprintf("Forbidden: %s is not permitted to access /resource", peerIDStr), http.StatusForbidden)
			return
		}

		log.Printf("Access ALLOWED for peer %s to /resource", peerIDStr)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "authorized",
			"data":           "synthetic_lab_resource_payload",
			"peer_spiffe_id": peerIDStr,
			"target_svid":    svid.ID.String(),
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/resource" {
			http.Error(w, "Forbidden: operation not permitted on protected resource", http.StatusForbidden)
			return
		}
	})

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Protected mTLS service listening on :8443")
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}

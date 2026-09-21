package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
 "net/http/httptrace"
 "time"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	socketPath := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socketPath == "" {
		socketPath = "unix:///tmp/spire-agent/public/api.sock"
	}
	targetURL := os.Getenv("TARGET_SERVICE_URL")
	if targetURL == "" {
		targetURL = "https://spiffe-service:8443"
	}

	ctx := context.Background()
	log.Printf("Caller connecting to SPIRE Workload API at %s...", socketPath)

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Failed to create caller X.509 source: %v", err)
	}
	defer source.Close()

	authorizer := tlsconfig.AdaptMatcher(func(id spiffeid.ID) error {
		if id.TrustDomain().String() != "lab.local" {
			return fmt.Errorf("unexpected peer trust domain: %s", id.TrustDomain())
		}
		return nil
	})

	tlsConfig := tlsconfig.MTLSClientConfig(source, source, authorizer)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy","service":"spiffe-caller"}`))
	})

	http.HandleFunc("/svid_info", func(w http.ResponseWriter, r *http.Request) {
		svid, err := source.GetX509SVID()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cert := svid.Certificates[0]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"spiffe_id":     svid.ID.String(),
			"serial_number": cert.SerialNumber.String(),
			"not_before":    cert.NotBefore.String(),
			"not_after":     cert.NotAfter.String(),
		})
	})

    http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
        probeClient := client
        if r.URL.Query().Get("fresh") == "true" {
            transport := &http.Transport{TLSClientConfig:tlsConfig, DisableKeepAlives:true}
            defer transport.CloseIdleConnections()
            probeClient = &http.Client{Transport:transport, Timeout:5*time.Second}
        }
        reused := false
        trace := &httptrace.ClientTrace{GotConn:func(info httptrace.GotConnInfo){reused=info.Reused}}
        req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(r.Context(),trace),http.MethodGet,targetURL+"/resource",nil)
        resp, err := probeClient.Do(req)
        w.Header().Set("Content-Type","application/json")
        if err != nil {
            w.WriteHeader(http.StatusBadGateway)
            json.NewEncoder(w).Encode(map[string]any{"target_status":nil,"connection_reused":reused,"error":"mTLS request unavailable"})
            return
        }
        defer resp.Body.Close()
        io.Copy(io.Discard,resp.Body)
        json.NewEncoder(w).Encode(map[string]any{"target_status":resp.StatusCode,"connection_reused":reused})
    })

	http.HandleFunc("/call", func(w http.ResponseWriter, r *http.Request) {
		resp, err := client.Get(fmt.Sprintf("%s/resource", targetURL))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "status": "failed"})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})

	http.HandleFunc("/call_forbidden", func(w http.ResponseWriter, r *http.Request) {
		resp, err := client.Get(fmt.Sprintf("%s/forbidden_op", targetURL))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "status": "failed"})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})

	log.Printf("Caller HTTP listening on :8003")
	if err := http.ListenAndServe(":8003", nil); err != nil {
		log.Fatalf("Caller server failed: %v", err)
	}
}

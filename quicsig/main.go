package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"quicsig/amnezia"
)

func main() {
	listen := env("LISTEN", "127.0.0.1:5000")
	origin := env("CORS_ORIGIN", "") // например https://warp.example.com; пусто = без CORS-заголовков

	mux := http.NewServeMux()
	mux.HandleFunc("/warp/quic_signature", func(w http.ResponseWriter, r *http.Request) {
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		}
		switch r.Method {
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
			return
		case http.MethodGet:
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}

		sni := strings.TrimSpace(r.URL.Query().Get("sni"))
		if sni == "" || len(sni) > 253 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid sni"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), amnezia.QUICSignatureTimeout)
		defer cancel()
		packets, err := amnezia.QUICSignature(ctx, sni)
		if err != nil {
			log.Printf("quic_signature sni=%q: %v", sni, err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, packets)
	})

	log.Printf("listening on %s", listen)
	log.Fatal((&http.Server{Addr: listen, Handler: mux}).ListenAndServe())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

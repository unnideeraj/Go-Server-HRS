package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync/atomic"
	"time"
)

const logFilePath = "frontend_full_request.log"

var requestCount uint64

func logFullRequest(r *http.Request, bodyCopy []byte) {
	// Dump the request without body, then append the actual body (since body is already read)
	dump, err := httputil.DumpRequest(r, false)
	if err != nil {
		log.Printf("[frontend] error dumping request: %v", err)
		return
	}
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[frontend] error opening log file: %v", err)
		return
	}
	defer f.Close()
	logEntry := fmt.Sprintf("%s\n%s\n%s\n---\n", time.Now().Format(time.RFC3339), dump, string(bodyCopy))
	if _, err := f.Write([]byte(logEntry)); err != nil {
		log.Printf("[frontend] error writing to log file: %v", err)
	}
}

func main() {
	backendURL, err := url.Parse("http://localhost:7071")
	if err != nil {
		log.Fatalf("Failed to parse backend URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddUint64(&requestCount, 1)
		log.Printf("[frontend] total requests received: %d", atomic.LoadUint64(&requestCount))

		// Read body for logging
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[frontend] error reading body: %v", err)
			http.Error(w, "cannot read body", http.StatusInternalServerError)
			return
		}

		// Log full request (headers + body)
		logFullRequest(r, body)

		// Reset the body for the proxy to read
		r.Body = io.NopCloser(bytes.NewReader(body))
		proxy.ServeHTTP(w, r)
	})

	log.Println("[frontend] listening on :7070")
	log.Fatal(http.ListenAndServe(":7070", nil))
}

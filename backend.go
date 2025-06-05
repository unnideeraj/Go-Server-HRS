package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"sync/atomic"
	"time"
)

const logFilePath = "backend_full_request.log"

var requestCount uint64

func logFullRequest(r *http.Request) {
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Printf("[backend] error dumping request: %v", err)
		return
	}
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[backend] error opening log file: %v", err)
		return
	}
	defer f.Close()
	logEntry := fmt.Sprintf("%s\n%s\n---\n", time.Now().Format(time.RFC3339), dump)
	if _, err := f.Write([]byte(logEntry)); err != nil {
		log.Printf("[backend] error writing to log file: %v", err)
	}
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddUint64(&requestCount, 1)
		log.Printf("[backend] total requests received: %d", atomic.LoadUint64(&requestCount))

		// Dump and log the full request (headers + body)
		logFullRequest(r)

		// Still consume the body to avoid issues
		io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, "<html><body><h1>Hello from Backend!</h1></body></html>")
	})

	log.Println("[backend] listening on :7071")
	log.Fatal(http.ListenAndServe(":7071", nil))
}

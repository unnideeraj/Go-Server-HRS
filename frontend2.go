package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	listenAddr  = ":7070"          // Frontend listens here
	backendAddr = "localhost:7071" // Backend address
	logFilePath = "frontend_full_request_2.log"
)

var requestCount uint64

func logFullRequest(data []byte) {
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("[frontend] error opening log file: %v", err)
		return
	}
	defer f.Close()
	logEntry := fmt.Sprintf("%s\n%s\n---\n", time.Now().Format(time.RFC3339), string(data))
	if _, err := f.Write([]byte(logEntry)); err != nil {
		log.Printf("[frontend] error writing to log file: %v", err)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("[frontend] error connecting to backend: %v", err)
		return
	}
	defer backendConn.Close()

	reader := bufio.NewReader(clientConn)

	// Read headers
	var headers []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[frontend] error reading header line: %v", err)
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" { // End of headers
			break
		}
		headers = append(headers, line)
	}

	// Parse Content-Length
	var contentLength int
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h), "content-length:") {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				clStr := strings.TrimSpace(parts[1])
				contentLength, err = strconv.Atoi(clStr)
				if err != nil {
					log.Printf("[frontend] invalid Content-Length: %v", err)
					contentLength = 0
				}
			}
			break
		}
	}

	// Reconstruct request headers with CRLF
	var rawRequest []byte
	for _, h := range headers {
		rawRequest = append(rawRequest, []byte(h+"\r\n")...)
	}
	rawRequest = append(rawRequest, []byte("\r\n")...)

	// Read body based on Content-Length
	body := make([]byte, contentLength)
	if contentLength > 0 {
		_, err = io.ReadFull(reader, body)
		if err != nil {
			log.Printf("[frontend] error reading body: %v", err)
			return
		}
	}

	rawRequest = append(rawRequest, body...)

	// Log full request and increment counter
	atomic.AddUint64(&requestCount, 1)
	log.Printf("[frontend] total requests received: %d", atomic.LoadUint64(&requestCount))
	logFullRequest(rawRequest)

	// Forward raw request to backend
	_, err = backendConn.Write(rawRequest)
	if err != nil {
		log.Printf("[frontend] error writing to backend: %v", err)
		return
	}

	// Pipe backend response back to client
	_, err = io.Copy(clientConn, backendConn)
	if err != nil {
		log.Printf("[frontend] error copying backend response: %v", err)
		return
	}
}

func main() {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("[frontend] failed to listen on %s: %v", listenAddr, err)
	}
	log.Printf("[frontend] listening on %s", listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[frontend] failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

// To run this frontend server:
// 1. Run your backend server on localhost:8081
// 2. Run this frontend server
// 3. Send requests to localhost:8080
// The frontend will parse requests using only Content-Length, log full requests, count requests, and forward raw requests to backend.

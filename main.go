package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"golang.org/x/time/rate"
)

var (
	mc          = memcache.New("127.0.0.1:11211")
	rateLimiter = rate.NewLimiter(1, 5)  // 1 request per second, burst up to 5 requests
	logQueue    = make(chan string, 100) // Log queue for asynchronous logging
	MaxLogSize  = 1024                   // Max size for a single log entry (1 KB)
)

const MaxRequestSize int64 = 1024 * 10 // Max request size (10 KB)

func transferLogsToETCD() {
	for {
		time.Sleep(1 * time.Hour)

		indexKey := "log-index"
		indexItem, err := mc.Get(indexKey)
		if err != nil {
			log.Println("No logs found in Memcached:", err)
			continue
		}

		logKeys := strings.Split(string(indexItem.Value), ",")

		for _, logKey := range logKeys {
			logItem, err := mc.Get(logKey)
			if err != nil {
				log.Printf("Failed to fetch log: %s\n", logKey)
				continue
			}

			fmt.Printf("Writing log to ETCD: %s -> %s\n", logKey, string(logItem.Value))
			mc.Delete(logKey)
		}

		mc.Delete(indexKey)
	}
}

func XSSProtectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rate limiting
		if !rateLimiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		// Request size limit
		if r.ContentLength > MaxRequestSize {
			http.Error(w, "Request size too large", http.StatusRequestEntityTooLarge)
			return
		}

		if r.URL.Path == "/admin" {
			next.ServeHTTP(w, r)
			return
		}

		if r.Method == http.MethodGet {
			queryParams := r.URL.Query()
			for key, values := range queryParams {
				for _, value := range values {
					if containsXSS(value) {
						logXSSAttemptAsync(fmt.Sprintf("Path:%s Param:%s Value:%s", r.URL.Path, key, value))
						http.Error(w, "Potential XSS detected", http.StatusBadRequest)
						return
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func containsXSS(input string) bool {
	potentialXSS := []string{
		"<script", "onerror=", "onload=", "javascript:", "alert(", "eval(",
		"data:text/html;base64,", "<iframe", "<img", "<svg", "<srcdoc", "prompt=",
	}
	input = strings.ToLower(input)
	for _, keyword := range potentialXSS {
		if strings.Contains(input, keyword) {
			return true
		}
	}
	if strings.Contains(input, "data:text/html;base64,") {
		decoded, err := decodeBase64Payload(input)
		if err == nil && containsXSS(decoded) {
			return true
		}
	}
	return false
}

func decodeBase64Payload(input string) (string, error) {
	parts := strings.Split(input, "data:text/html;base64,")
	if len(parts) < 2 {
		return "", fmt.Errorf("Base64 format error")
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	return string(decodedBytes), nil
}

func logProcessor() {
	for logData := range logQueue {
		log.Println("Processed log:", logData)
	}
}

func logXSSAttemptAsync(data string) {
	if len(data) > MaxLogSize {
		data = data[:MaxLogSize] + "... (truncated)"
	}
	select {
	case logQueue <- data:
		// Log added to queue
	default:
		// Queue is full, drop log
		log.Println("Log queue full, dropping log:", data)
	}
}

func main() {
	// Start the log processor in a separate goroutine
	go logProcessor()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Request accepted!")
	})

	http.Handle("/", XSSProtectionMiddleware(handler))
	go transferLogsToETCD()
	fmt.Println("Server running on :8080")
	http.ListenAndServe(":8080", nil)
}

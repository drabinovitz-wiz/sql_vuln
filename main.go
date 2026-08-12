package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os/exec"
)

// SQL Injection Vulnerability
// Querying a user using raw string formatting rather than parameterized inputs
func getUserHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("id")
		if userID == "" {
			http.Error(w, "Missing ID parameter", http.StatusBadRequest)
			return
		}

		// Vulnerability: Direct string interpolation (SQL Injection)
		query := fmt.Sprintf("SELECT username, email FROM users WHERE id = '%s'", userID)
		
		var username, email string
		err := db.QueryRow(query).Scan(&username, &email)
		if err != nil {
			http.Error(w, "User not found or query error", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "User Found: %s (%s)", username, email)
	}
}

// Command Injection Vulnerability
// Passing untrusted user input directly to a shell executor
func pingHostHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "Missing host parameter", http.StatusBadRequest)
		return
	}

	// Vulnerability: Shell execution with unvalidated user input (Command Injection)
	// Example malicious input: host=127.0.0.1;cat /etc/passwd
	cmdString := fmt.Sprintf("ping -c 3 %s", host)
	out, err := exec.Command("sh", "-c", cmdString).CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Execution failed: %s", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Output:\n%s", out)
}

func main() {
	// Dummy in-memory DB connection setup
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatalf("Failed to open DB: %s", err)
	}
	defer db.Close()

	http.HandleFunc("/user", getUserHandler(db))
	http.HandleFunc("/ping", pingHostHandler)

	fmt.Println("Vulnerable Go Server running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

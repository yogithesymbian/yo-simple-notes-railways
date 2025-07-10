package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
)

type Note struct {
	ID         int        `json:"id"`
	Title      string     `json:"title"`
	Content    string     `json:"content"`
	MarkDone   bool       `json:"mark_done"`
	Synced     bool       `json:"synced"`
	CreatedAt  time.Time  `json:"created_at"`
	MarkDoneAt *time.Time `json:"mark_done_at"`
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var db *sql.DB
var jwtSecret []byte

func main() {
	_ = godotenv.Load()

	jwtSecret = []byte(os.Getenv("JWT_SECRET"))

	var err error
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		dsn = formatDSNFromURL(os.Getenv("DATABASE_URL"))
	}

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	handleRoutes()
}

func formatDSNFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic("Invalid DATABASE_URL")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	host := u.Host
	dbName := strings.TrimPrefix(u.Path, "/")
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8mb4&parseTime=true&loc=Local", user, pass, host, dbName)
}

func handleRoutes() {
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/notes/offline-process", syncNoteHandler).Methods("POST")

	noteRoutes := r.PathPrefix("/notes").Subrouter()
	noteRoutes.Use(authMiddleware)
	noteRoutes.HandleFunc("", getNotes).Methods("GET")
	noteRoutes.HandleFunc("/{id}", getNote).Methods("GET")
	noteRoutes.HandleFunc("", createNote).Methods("POST")
	noteRoutes.HandleFunc("/{id}", updateNote).Methods("PUT")
	noteRoutes.HandleFunc("/{id}", deleteNote).Methods("DELETE")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Server is running at http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// =================================== AUTH ===================================

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var u User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	u.Username = strings.TrimSpace(u.Username)
	u.Password = strings.TrimSpace(u.Password)

	var hashedPassword []byte
	err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", u.Username).Scan(&u.ID, &hashedPassword)
	if err != nil || bcrypt.CompareHashAndPassword(hashedPassword, []byte(u.Password)) != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": u.ID,
		"exp":     time.Now().Add(72 * time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ================================ NOTE CRUD =================================

func getNotes(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, title, content, mark_done, synced, created_at, mark_done_at FROM notes")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var (
			n             Note
			createdAtRaw  sql.NullTime
			markDoneAtRaw sql.NullTime
		)

		err := rows.Scan(
			&n.ID,
			&n.Title,
			&n.Content,
			&n.MarkDone,
			&n.Synced,
			&createdAtRaw,
			&markDoneAtRaw,
		)
		if err != nil {
			http.Error(w, fmt.Sprintf("Scan error: %v", err), http.StatusInternalServerError)
			return
		}

		if createdAtRaw.Valid {
			n.CreatedAt = createdAtRaw.Time
		} else {
			n.CreatedAt = time.Time{} // zero time
		}

		if markDoneAtRaw.Valid {
			n.MarkDoneAt = &markDoneAtRaw.Time
		} else {
			n.MarkDoneAt = nil
		}

		notes = append(notes, n)
	}

	// encode JSON with proper datetime formatting
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(notes); err != nil {
		http.Error(w, "JSON Encode Error", http.StatusInternalServerError)
	}
}


func getNote(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var (
		n             Note
		createdAtRaw  sql.NullTime
		markDoneAtRaw sql.NullTime
	)

	err := db.QueryRow("SELECT id, title, content, mark_done, synced, created_at, mark_done_at FROM notes WHERE id = ?", id).
		Scan(&n.ID, &n.Title, &n.Content, &n.MarkDone, &n.Synced, &createdAtRaw, &markDoneAtRaw)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	if createdAtRaw.Valid {
		n.CreatedAt = createdAtRaw.Time
	}
	if markDoneAtRaw.Valid {
		n.MarkDoneAt = &markDoneAtRaw.Time
	}
	json.NewEncoder(w).Encode(n)
}

func createNote(w http.ResponseWriter, r *http.Request) {
	var n Note
	_ = json.NewDecoder(r.Body).Decode(&n)

	var markDoneAt interface{}
	if n.MarkDoneAt != nil && !n.MarkDoneAt.IsZero() {
		markDoneAt = *n.MarkDoneAt
	} else {
		markDoneAt = nil
	}

	_, err := db.Exec(`
		INSERT INTO notes (title, content, mark_done, synced, mark_done_at)
		VALUES (?, ?, ?, ?, ?)`,
		n.Title, n.Content, n.MarkDone, false, markDoneAt,
	)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Note created"})
}


func updateNote(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var n Note
	_ = json.NewDecoder(r.Body).Decode(&n)

	_, err := db.Exec(`UPDATE notes SET title = ?, content = ?, mark_done = ?, mark_done_at = ? WHERE id = ?`,
		n.Title, n.Content, n.MarkDone, n.MarkDoneAt, id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": "Note updated"})
}

func deleteNote(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_, err := db.Exec("DELETE FROM notes WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ============================= SYNC OFFLINE DATA ============================

func syncNoteHandler(w http.ResponseWriter, r *http.Request) {
	var note Note
	if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM notes WHERE id = ?)", note.ID).Scan(&exists)
	if err != nil {
		http.Error(w, "DB Check Error", http.StatusInternalServerError)
		return
	}

	if exists {
		_, err = db.Exec(`UPDATE notes SET title = ?, content = ?, mark_done = ?, created_at = ?, mark_done_at = ?, synced = 1 WHERE id = ?`,
			note.Title, note.Content, note.MarkDone, note.CreatedAt, note.MarkDoneAt, note.ID)
	} else {
		_, err = db.Exec(`INSERT INTO notes (id, title, content, mark_done, created_at, mark_done_at, synced)
			VALUES (?, ?, ?, ?, ?, ?, 1)`,
			note.ID, note.Title, note.Content, note.MarkDone, note.CreatedAt, note.MarkDoneAt)
	}

	if err != nil {
		http.Error(w, "DB Operation Failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Note synced successfully"})
}

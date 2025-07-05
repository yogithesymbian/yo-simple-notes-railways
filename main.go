// go-notes-crud/main.go
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/go-sql-driver/mysql"
)

type Note struct {
	ID       int    `json:"id"`
	Title    string `json:"title"`
	Content  string `json:"content"`
	MarkDone bool   `json:"mark_done"`
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var db *sql.DB
var jwtSecret []byte

func main() {
	_ = godotenv.Load() // load local .env (optional, ignored in Railway)

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
		panic("invalid DATABASE_URL")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	host := u.Host
	dbName := strings.TrimPrefix(u.Path, "/")

	return fmt.Sprintf("%s:%s@tcp(%s)/%s", user, pass, host, dbName)
}

func handleRoutes() {
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")

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

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var u User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	u.Username = strings.TrimSpace(u.Username)
	u.Password = strings.TrimSpace(u.Password)

	var hashedPassword []byte
	err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", u.Username).
		Scan(&u.ID, &hashedPassword)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(u.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": u.ID,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
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
		if tokenString == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

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

func getNotes(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, title, content, mark_done FROM notes")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var n Note
		err := rows.Scan(&n.ID, &n.Title, &n.Content, &n.MarkDone)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		notes = append(notes, n)
	}
	json.NewEncoder(w).Encode(notes)
}

func getNote(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var n Note
	err := db.QueryRow("SELECT id, title, content, mark_done FROM notes WHERE id = ?", id).
		Scan(&n.ID, &n.Title, &n.Content, &n.MarkDone)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(n)
}

func createNote(w http.ResponseWriter, r *http.Request) {
	var n Note
	_ = json.NewDecoder(r.Body).Decode(&n)

	res, err := db.Exec("INSERT INTO notes (title, content, mark_done) VALUES (?, ?, ?)", n.Title, n.Content, n.MarkDone)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	id, _ := res.LastInsertId()
	n.ID = int(id)
	json.NewEncoder(w).Encode(n)
}

func updateNote(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var n Note
	_ = json.NewDecoder(r.Body).Decode(&n)

	_, err := db.Exec("UPDATE notes SET title = ?, content = ?, mark_done = ? WHERE id = ?", n.Title, n.Content, n.MarkDone, id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	n.ID = atoi(id)
	json.NewEncoder(w).Encode(n)
}

func deleteNote(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	_, err := db.Exec("DELETE FROM notes WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db      *sql.DB
	tokMap  = map[string]int64{}
	tokMu   sync.RWMutex
)

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func storeToken(token string, userID int64) {
	tokMu.Lock()
	tokMap[token] = userID
	tokMu.Unlock()
}

func lookupToken(token string) (int64, bool) {
	tokMu.RLock()
	id, ok := tokMap[token]
	tokMu.RUnlock()
	return id, ok
}

func bearerAuth(r *http.Request) (int64, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return 0, false
	}
	return lookupToken(strings.TrimPrefix(auth, "Bearer "))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var userID int64
	err = db.QueryRowContext(r.Context(),
		`INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id`,
		req.Username, string(hash),
	).Scan(&userID)
	if err != nil {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}

	token, err := generateToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	storeToken(token, userID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"user_id":       userID,
		"session_token": token,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var userID int64
	var hash string
	err := db.QueryRowContext(r.Context(),
		`SELECT id, password_hash FROM users WHERE username = $1`,
		req.Username,
	).Scan(&userID, &hash)
	if err == sql.ErrNoRows {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := generateToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	storeToken(token, userID)

	writeJSON(w, http.StatusOK, map[string]any{"session_token": token})
}

func handleGetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := bearerAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var u struct {
		UserID      int64   `json:"user_id"`
		Username    string  `json:"username"`
		DisplayName *string `json:"display_name"`
		Bio         *string `json:"bio"`
	}
	u.UserID = userID
	err := db.QueryRowContext(r.Context(),
		`SELECT username, display_name, bio FROM users WHERE id = $1`,
		userID,
	).Scan(&u.Username, &u.DisplayName, &u.Bio)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, u)
}

func handlePatchMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := bearerAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		DisplayName *string `json:"display_name"`
		Bio         *string `json:"bio"`
		Password    *string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.DisplayName != nil {
		if _, err := db.ExecContext(r.Context(),
			`UPDATE users SET display_name = $1 WHERE id = $2`,
			*req.DisplayName, userID,
		); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	if req.Bio != nil {
		if _, err := db.ExecContext(r.Context(),
			`UPDATE users SET bio = $1 WHERE id = $2`,
			*req.Bio, userID,
		); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	if req.Password != nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if _, err := db.ExecContext(r.Context(),
			`UPDATE users SET password_hash = $1 WHERE id = $2`,
			string(hash), userID,
		); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleGetUser(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")

	var u struct {
		UserID      int64   `json:"user_id"`
		Username    string  `json:"username"`
		DisplayName *string `json:"display_name"`
		Bio         *string `json:"bio"`
	}
	err := db.QueryRowContext(r.Context(),
		`SELECT id, username, display_name, bio FROM users WHERE username = $1`,
		username,
	).Scan(&u.UserID, &u.Username, &u.DisplayName, &u.Bio)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, u)
}

func handleListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.QueryContext(r.Context(),
		`SELECT id, username, display_name FROM users ORDER BY id`,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type userItem struct {
		UserID      int64   `json:"user_id"`
		Username    string  `json:"username"`
		DisplayName *string `json:"display_name"`
	}
	users := []userItem{}
	for rows.Next() {
		var u userItem
		if err := rows.Scan(&u.UserID, &u.Username, &u.DisplayName); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, users)
}

func handleCreatePost(w http.ResponseWriter, r *http.Request) {
	userID, ok := bearerAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Body == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var post struct {
		ID        int64     `json:"id"`
		UserID    int64     `json:"user_id"`
		Body      string    `json:"body"`
		CreatedAt time.Time `json:"created_at"`
	}
	post.UserID = userID
	post.Body = req.Body
	err := db.QueryRowContext(r.Context(),
		`INSERT INTO posts (user_id, body) VALUES ($1, $2) RETURNING id, created_at`,
		userID, req.Body,
	).Scan(&post.ID, &post.CreatedAt)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, post)
}

func handleGetPostsByUsername(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")

	rows, err := db.QueryContext(r.Context(),
		`SELECT p.id, p.user_id, p.body, p.created_at
		 FROM posts p
		 JOIN users u ON u.id = p.user_id
		 WHERE u.username = $1
		 ORDER BY p.created_at DESC
		 LIMIT 50`,
		username,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type postItem struct {
		ID        int64     `json:"id"`
		UserID    int64     `json:"user_id"`
		Body      string    `json:"body"`
		CreatedAt time.Time `json:"created_at"`
	}
	posts := []postItem{}
	for rows.Next() {
		var p postItem
		if err := rows.Scan(&p.ID, &p.UserID, &p.Body, &p.CreatedAt); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		posts = append(posts, p)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, posts)
}

func handleFollow(w http.ResponseWriter, r *http.Request) {
	followerID, ok := bearerAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	username := r.PathValue("username")
	var followeeID int64
	err := db.QueryRowContext(r.Context(),
		`SELECT id FROM users WHERE username = $1`, username,
	).Scan(&followeeID)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_, err = db.ExecContext(r.Context(),
		`INSERT INTO follows (follower_id, followee_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		followerID, followeeID,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func handleUnfollow(w http.ResponseWriter, r *http.Request) {
	followerID, ok := bearerAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	username := r.PathValue("username")
	var followeeID int64
	err := db.QueryRowContext(r.Context(),
		`SELECT id FROM users WHERE username = $1`, username,
	).Scan(&followeeID)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_, err = db.ExecContext(r.Context(),
		`DELETE FROM follows WHERE follower_id = $1 AND followee_id = $2`,
		followerID, followeeID,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func handleFollowStatus(w http.ResponseWriter, r *http.Request) {
	followerID, ok := bearerAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var followeeID int64
	err := db.QueryRowContext(r.Context(),
		`SELECT id FROM users WHERE username = $1`, username,
	).Scan(&followeeID)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusOK, map[string]bool{"following": false})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var count int
	if err := db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM follows WHERE follower_id = $1 AND followee_id = $2`,
		followerID, followeeID,
	).Scan(&count); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"following": count > 0})
}

func handleTimeline(w http.ResponseWriter, r *http.Request) {
	userID, ok := bearerAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.QueryContext(r.Context(),
		`SELECT p.id, p.user_id, p.body, p.created_at
		 FROM posts p
		 WHERE p.user_id = $1
		    OR p.user_id IN (SELECT followee_id FROM follows WHERE follower_id = $1)
		 ORDER BY p.created_at DESC
		 LIMIT 50`,
		userID,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type postItem struct {
		ID        int64     `json:"id"`
		UserID    int64     `json:"user_id"`
		Body      string    `json:"body"`
		CreatedAt time.Time `json:"created_at"`
	}
	posts := []postItem{}
	for rows.Next() {
		var p postItem
		if err := rows.Scan(&p.ID, &p.UserID, &p.Body, &p.CreatedAt); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		posts = append(posts, p)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, posts)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/signup", handleSignup)
	mux.HandleFunc("POST /api/auth/login", handleLogin)
	mux.HandleFunc("GET /api/users/me", handleGetMe)
	mux.HandleFunc("PATCH /api/users/me", handlePatchMe)
	mux.HandleFunc("GET /api/users/{username}", handleGetUser)
	mux.HandleFunc("GET /api/users", handleListUsers)
	mux.HandleFunc("POST /api/posts", handleCreatePost)
	mux.HandleFunc("GET /api/posts/by/{username}", handleGetPostsByUsername)
	mux.HandleFunc("POST /api/follow/{username}", handleFollow)
	mux.HandleFunc("DELETE /api/follow/{username}", handleUnfollow)
	mux.HandleFunc("GET /api/follow/status", handleFollowStatus)
	mux.HandleFunc("GET /api/timeline", handleTimeline)
	mux.HandleFunc("GET /healthz", handleHealthz)

	log.Printf("listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

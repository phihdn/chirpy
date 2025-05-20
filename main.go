package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"github.com/phihdn/chirpy/internal/auth"
	"github.com/phihdn/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	jwtSecret      string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) getMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	response := fmt.Sprintf(
		"<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>",
		cfg.fileserverHits.Load(),
	)
	w.Write([]byte(response))
}

func (cfg *apiConfig) resetMetrics(w http.ResponseWriter, r *http.Request) {
	// Check if platform is dev
	if cfg.platform != "dev" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Not allowed in this environment"})
		return
	}

	// Reset metrics counter
	cfg.fileserverHits.Store(0)

	// Delete all users from the database
	err := cfg.dbQueries.DeleteAllUsers(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to delete users"})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	response := fmt.Sprintf("Hits reset to: %d and all users deleted\n", cfg.fileserverHits.Load())
	w.Write([]byte(response))
}

func cleanChirp(body string) string {
	profaneWords := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}
	words := strings.Fields(body)
	cleanedWords := make([]string, len(words))
	for i, word := range words {
		lowerWord := strings.ToLower(word)
		if _, ok := profaneWords[lowerWord]; ok {
			cleanedWords[i] = "****"
		} else {
			cleanedWords[i] = word
		}
	}
	return strings.Join(cleanedWords, " ")
}

func main() {
	godotenv.Load()
	dbUrl := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	jwtSecret := os.Getenv("JWT_SECRET")

	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	const port = "8080"

	mux := http.NewServeMux()

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	dbQueries := database.New(db)
	apiCfg := &apiConfig{
		dbQueries: dbQueries,
		platform:  platform,
		jwtSecret: jwtSecret,
	}

	fileServerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.StripPrefix("/app/", http.FileServer(http.Dir("."))).ServeHTTP(w, r)
	})

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fileServerHandler))
	mux.Handle("GET /api/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	mux.Handle(
		"POST /api/chirps",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			type parameters struct {
				Body string `json:"body"`
			}

			type errorResponse struct {
				Error string `json:"error"`
			}

			type chirpResponse struct {
				ID        string    `json:"id"`
				CreatedAt time.Time `json:"created_at"`
				UpdatedAt time.Time `json:"updated_at"`
				Body      string    `json:"body"`
				UserID    string    `json:"user_id"`
			}

			// Extract the bearer token from the Authorization header
			bearerToken, err := auth.GetBearerToken(r.Header)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{Error: "Authentication required"})
				return
			}

			// Validate the JWT and get the user ID
			userID, err := auth.ValidateJWT(bearerToken, apiCfg.jwtSecret)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{Error: "Invalid authentication token"})
				return
			}

			decoder := json.NewDecoder(r.Body)
			params := parameters{}
			err = decoder.Decode(&params)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(errorResponse{Error: "Something went wrong"})
				return
			}

			if len(params.Body) > 140 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(errorResponse{Error: "Chirp is too long"})
				return
			}

			// Clean the chirp
			cleanedBody := cleanChirp(params.Body)

			// Create chirp in database
			chirp, err := apiCfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
				Body:   cleanedBody,
				UserID: userID,
			})
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errorResponse{Error: "Error creating chirp"})
				return
			}

			// Prepare response
			response := chirpResponse{
				ID:        chirp.ID.String(),
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    chirp.UserID.String(),
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(response)
		}),
	)

	mux.Handle(
		"POST /api/users",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			type parameters struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}

			type userResponse struct {
				ID        string    `json:"id"`
				CreatedAt time.Time `json:"created_at"`
				UpdatedAt time.Time `json:"updated_at"`
				Email     string    `json:"email"`
			}

			type errorResponse struct {
				Error string `json:"error"`
			}

			decoder := json.NewDecoder(r.Body)
			params := parameters{}
			err := decoder.Decode(&params)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(errorResponse{Error: "Something went wrong"})
				return
			}

			// Validate required fields
			if params.Email == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(errorResponse{Error: "Email is required"})
				return
			}

			if params.Password == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(errorResponse{Error: "Password is required"})
				return
			}

			// Hash the password
			hashedPassword, err := auth.HashPassword(params.Password)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errorResponse{Error: "Error hashing password"})
				return
			}

			// Create user in database
			user, err := apiCfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
				Email:          params.Email,
				HashedPassword: hashedPassword,
			})
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errorResponse{Error: "Error creating user"})
				return
			}

			// Prepare response (do not include the hashed password)
			response := userResponse{
				ID:        user.ID.String(),
				CreatedAt: user.CreatedAt,
				UpdatedAt: user.UpdatedAt,
				Email:     user.Email,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(response)
		}),
	)

	mux.Handle(
		"POST /api/login",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			type parameters struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}

			type userResponse struct {
				ID           string    `json:"id"`
				CreatedAt    time.Time `json:"created_at"`
				UpdatedAt    time.Time `json:"updated_at"`
				Email        string    `json:"email"`
				Token        string    `json:"token"`
				RefreshToken string    `json:"refresh_token"`
			}

			type errorResponse struct {
				Error string `json:"error"`
			}

			decoder := json.NewDecoder(r.Body)
			params := parameters{}
			err := decoder.Decode(&params)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(errorResponse{Error: "Something went wrong"})
				return
			}

			// Look up the user by email
			user, err := apiCfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
			if err != nil {
				// Don't reveal that the user doesn't exist
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{Error: "Incorrect email or password"})
				return
			}

			// Check if the password matches the stored hash
			err = auth.CheckPasswordHash(user.HashedPassword, params.Password)
			if err != nil {
				// Password doesn't match
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{Error: "Incorrect email or password"})
				return
			}

			// Access token (JWT) expires in 1 hour
			accessTokenExpiry := time.Hour

			// Create JWT token
			token, err := auth.MakeJWT(user.ID, apiCfg.jwtSecret, accessTokenExpiry)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errorResponse{Error: "Error creating authentication token"})
				return
			}

			// Generate refresh token (expires in 60 days)
			refreshToken, err := auth.MakeRefreshToken()
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errorResponse{Error: "Error creating refresh token"})
				return
			}

			// Store refresh token in database
			refreshTokenExpiry := time.Now().Add(60 * 24 * time.Hour) // 60 days
			_, err = apiCfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
				Token:     refreshToken,
				UserID:    user.ID,
				ExpiresAt: refreshTokenExpiry,
			})
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errorResponse{Error: "Error storing refresh token"})
				return
			}

			// Create the response with access token and refresh token
			response := userResponse{
				ID:           user.ID.String(),
				CreatedAt:    user.CreatedAt,
				UpdatedAt:    user.UpdatedAt,
				Email:        user.Email,
				Token:        token,
				RefreshToken: refreshToken,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		}),
	)

	mux.Handle(
		"POST /api/refresh",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			type tokenResponse struct {
				Token string `json:"token"`
			}

			type errorResponse struct {
				Error string `json:"error"`
			}

			// Extract the bearer token from the Authorization header
			refreshTokenStr, err := auth.GetBearerToken(r.Header)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{Error: "Authentication required"})
				return
			}

			// Look up the refresh token in the database
			refreshToken, err := apiCfg.dbQueries.GetRefreshToken(r.Context(), refreshTokenStr)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{Error: "Invalid refresh token"})
				return
			}

			// Check if the token is expired
			if time.Now().After(refreshToken.ExpiresAt) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{Error: "Refresh token expired"})
				return
			}

			// Check if the token has been revoked
			if refreshToken.RevokedAt.Valid {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{Error: "Refresh token revoked"})
				return
			}

			// Create a new access token with 1 hour expiration
			accessTokenExpiry := time.Hour
			newToken, err := auth.MakeJWT(refreshToken.UserID, apiCfg.jwtSecret, accessTokenExpiry)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errorResponse{Error: "Error creating authentication token"})
				return
			}

			// Respond with the new access token
			response := tokenResponse{
				Token: newToken,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		}),
	)

	mux.Handle(
		"POST /api/revoke",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			type errorResponse struct {
				Error string `json:"error"`
			}

			// Extract the bearer token from the Authorization header
			refreshTokenStr, err := auth.GetBearerToken(r.Header)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{Error: "Authentication required"})
				return
			}

			// Revoke the refresh token in the database
			err = apiCfg.dbQueries.RevokeRefreshToken(r.Context(), refreshTokenStr)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errorResponse{Error: "Error revoking token"})
				return
			}

			// Respond with 204 No Content (success, but no body)
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	mux.Handle(
		"PUT /api/users",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			type parameters struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}

			type userResponse struct {
				ID        string    `json:"id"`
				CreatedAt time.Time `json:"created_at"`
				UpdatedAt time.Time `json:"updated_at"`
				Email     string    `json:"email"`
			}

			type errorResponse struct {
				Error string `json:"error"`
			}

			// Extract the bearer token from the Authorization header
			bearerToken, err := auth.GetBearerToken(r.Header)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{Error: "Authentication required"})
				return
			}

			// Validate the JWT and get the user ID
			userID, err := auth.ValidateJWT(bearerToken, apiCfg.jwtSecret)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{Error: "Invalid authentication token"})
				return
			}

			// Parse the request body
			decoder := json.NewDecoder(r.Body)
			params := parameters{}
			err = decoder.Decode(&params)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(errorResponse{Error: "Invalid request body"})
				return
			}

			// Validate required fields
			if params.Email == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(errorResponse{Error: "Email is required"})
				return
			}

			if params.Password == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(errorResponse{Error: "Password is required"})
				return
			}

			// Hash the new password
			hashedPassword, err := auth.HashPassword(params.Password)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errorResponse{Error: "Error hashing password"})
				return
			}

			// Update user in database
			updatedUser, err := apiCfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
				Email:          params.Email,
				HashedPassword: hashedPassword,
				ID:             userID,
			})
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errorResponse{Error: "Error updating user"})
				return
			}

			// Prepare response (do not include the hashed password)
			response := userResponse{
				ID:        updatedUser.ID.String(),
				CreatedAt: updatedUser.CreatedAt,
				UpdatedAt: updatedUser.UpdatedAt,
				Email:     updatedUser.Email,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		}),
	)

	mux.Handle("GET /admin/metrics", http.HandlerFunc(apiCfg.getMetrics))
	mux.Handle("POST /admin/reset", http.HandlerFunc(apiCfg.resetMetrics))

	mux.Handle(
		"GET /api/chirps",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			type chirpResponse struct {
				ID        string    `json:"id"`
				CreatedAt time.Time `json:"created_at"`
				UpdatedAt time.Time `json:"updated_at"`
				Body      string    `json:"body"`
				UserID    string    `json:"user_id"`
			}

			type errorResponse struct {
				Error string `json:"error"`
			}

			// Get all chirps from database
			chirps, err := apiCfg.dbQueries.GetAllChirps(r.Context())
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errorResponse{Error: "Error retrieving chirps"})
				return
			}

			// Convert the database chirps to response format
			response := make([]chirpResponse, len(chirps))
			for i, chirp := range chirps {
				response[i] = chirpResponse{
					ID:        chirp.ID.String(),
					CreatedAt: chirp.CreatedAt,
					UpdatedAt: chirp.UpdatedAt,
					Body:      chirp.Body,
					UserID:    chirp.UserID.String(),
				}
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		}),
	)

	mux.Handle(
		"GET /api/chirps/{chirpID}",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get chirp ID from path parameter
			chirpIDStr := r.PathValue("chirpID")

			type chirpResponse struct {
				ID        string    `json:"id"`
				CreatedAt time.Time `json:"created_at"`
				UpdatedAt time.Time `json:"updated_at"`
				Body      string    `json:"body"`
				UserID    string    `json:"user_id"`
			}

			type errorResponse struct {
				Error string `json:"error"`
			}

			// Parse chirp ID into UUID
			chirpID, err := uuid.Parse(chirpIDStr)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(errorResponse{Error: "Invalid chirp ID format"})
				return
			}

			// Get chirp from database
			chirp, err := apiCfg.dbQueries.GetChirpByID(r.Context(), chirpID)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(errorResponse{Error: "Chirp not found"})
				return
			}

			// Prepare response
			response := chirpResponse{
				ID:        chirp.ID.String(),
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    chirp.UserID.String(),
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		}),
	)

	log.Printf("Serving on port: %s\n", port)
	log.Fatal(srv.ListenAndServe())
}

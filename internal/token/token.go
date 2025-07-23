package token

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

type Claims struct {
	Sub       string `json:"sub"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

type RefreshToken struct {
	ID        int       `db:"id"`
	UserGUID  string    `db:"user_guid"`
	SessionID string    `db:"session_id"`
	TokenHash string    `db:"token_hash"`
	UserAgent string    `db:"user_agent"`
	IPAddress string    `db:"ip_address"`
	CreatedAt time.Time `db:"created_at"`
	ExpiresAt time.Time `db:"expires_at"`
	IsValid   bool      `db:"is_valid"`
}

func GenerateTokens(db *pgxpool.Pool, userGUID, userAgent, ipAddress, jwtSecret string) (string, string, error) {
	_, err := db.Exec(context.Background(), `UPDATE refresh_tokens SET is_valid = false WHERE user_guid = $1`, userGUID)
	if err != nil {
		return "", "", err
	}

	sessionID := uuid.New().String()

	claims := Claims{
		Sub:       userGUID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessTokenString, err := accessToken.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", "", err
	}

	rawRefreshToken := generateRandomString(32)
	refreshToken := base64.StdEncoding.EncodeToString([]byte(rawRefreshToken))
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(rawRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	query := `
		INSERT INTO refresh_tokens (user_guid, session_id, token_hash, user_agent, ip_address, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	_, err = db.Exec(context.Background(), query, userGUID, sessionID, string(tokenHash), userAgent, ipAddress, expiresAt)
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshToken, nil
}

func ValidateRefreshToken(db *pgxpool.Pool, refreshToken, userGUID, sessionID, userAgent, ipAddress, webhookURL string) (*RefreshToken, error) {
	rawRefreshToken, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		return nil, err
	}

	var storedToken RefreshToken
	query := `
		SELECT id, session_id, token_hash, user_guid, user_agent, ip_address, is_valid, expires_at 
		FROM refresh_tokens 
		WHERE user_guid = $1 AND is_valid = true
	`
	err = db.QueryRow(context.Background(), query, userGUID).Scan(
		&storedToken.ID, &storedToken.SessionID, &storedToken.TokenHash,
		&storedToken.UserGUID, &storedToken.UserAgent, &storedToken.IPAddress,
		&storedToken.IsValid, &storedToken.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}

	if storedToken.SessionID != sessionID {
		return nil, errors.New("token pair mismatch")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedToken.TokenHash), rawRefreshToken); err != nil {
		return nil, err
	}

	if time.Now().After(storedToken.ExpiresAt) {
		return nil, errors.New("refresh token expired")
	}

	if storedToken.UserAgent != userAgent {
		_, err := db.Exec(context.Background(), `UPDATE refresh_tokens SET is_valid = false WHERE id = $1`, storedToken.ID)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("user-agent mismatch")
	}

	if storedToken.IPAddress != ipAddress && webhookURL != "" {
		go sendWebhook(userGUID, ipAddress, webhookURL)
	}

	return &storedToken, nil
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sendWebhook(userGUID, newIP, webhookURL string) {
	data := map[string]string{
		"user_guid": userGUID,
		"new_ip":    newIP,
		"timestamp": time.Now().Format(time.RFC3339),
	}
	body, _ := json.Marshal(data)
	_, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return
	}

}

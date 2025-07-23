package api

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"medods-task/internal/config"
	"medods-task/internal/token"
	"net/http"
	"strings"
	"time"
)

// @title Auth Service API
// @version 1.0
// @description API для аутентификации пользователей
// @host localhost:8080
// @BasePath /
func SetupRoutes(r *gin.Engine, db *pgxpool.Pool, cfg *config.Config) {
	r.GET("/token", getToken(db, cfg))
	r.POST("/refresh", refreshToken(db, cfg))
	r.GET("/me", authMiddleware(db, cfg), getUserGUID())
	r.POST("/logout", authMiddleware(db, cfg), logout(db))
}

// @Summary Получение пары токенов
// @Description Выдает access и refresh токены для указанного GUID
// @Tags auth
// @Accept json
// @Produce json
// @Param guid query string true "GUID пользователя"
// @Success 200 {object} map[string]string
// @Failure 400 {string} string "Invalid GUID"
// @Failure 500 {string} string "Internal server error"
// @Router /token [get]
func getToken(db *pgxpool.Pool, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		guid := c.Query("guid")
		if guid == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid GUID"})
			return
		}

		accessToken, refreshToken, err := token.GenerateTokens(db, guid, c.Request.UserAgent(), c.ClientIP(), cfg.JWTSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
			log.Print("Failed to generate tokens: ", err)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}
}

type RefreshRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// @Summary Обновление токенов
// @Description Обновляет пару токенов
// @Tags auth
// @Accept json
// @Produce json
// @Param body body RefreshRequest true "Токены"
// @Success 200 {object} map[string]string
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Invalid tokens"
// @Router /refresh [post]
func refreshToken(db *pgxpool.Pool, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			log.Print("Invalid request: ", err)
			return
		}

		claims := &token.Claims{}
		tkn, err := jwt.ParseWithClaims(req.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		})
		if err != nil || !tkn.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid access token"})
			return
		}

		storedToken, err := token.ValidateRefreshToken(db, req.RefreshToken, claims.Sub, claims.SessionID, c.Request.UserAgent(), c.ClientIP(), cfg.WebhookURL)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		_, err = db.Exec(context.Background(), `UPDATE refresh_tokens SET is_valid = false WHERE id = $1`, storedToken.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		accessToken, refreshToken, err := token.GenerateTokens(db, claims.Sub, c.Request.UserAgent(), c.ClientIP(), cfg.JWTSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}
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

func authMiddleware(db *pgxpool.Pool, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &token.Claims{}
		tkn, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		})
		if err != nil || !tkn.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		var storedToken RefreshToken
		query := `SELECT id, is_valid, expires_at 
		          FROM refresh_tokens 
		          WHERE user_guid = $1 AND session_id = $2 AND is_valid = true`
		err = db.QueryRow(context.Background(), query, claims.Sub, claims.SessionID).Scan(
			&storedToken.ID, &storedToken.IsValid, &storedToken.ExpiresAt,
		)
		if err != nil || !storedToken.IsValid || time.Now().After(storedToken.ExpiresAt) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is invalid or expired"})
			c.Abort()
			return
		}

		c.Set("user_guid", claims.Sub)
		c.Next()
	}
}

// @Summary Получение GUID пользователя
// @Description Возвращает GUID текущего пользователя
// @Tags auth
// @Security ApiKeyAuth
// @Produce json
// @Param Authorization header string  true "Access-токен"
// @Success 200 {object} map[string]string
// @Failure 401 {string} string "Unauthorized"
// @Router /me [get]
func getUserGUID() gin.HandlerFunc {
	return func(c *gin.Context) {
		guid, exists := c.Get("user_guid")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"guid": guid})
	}
}

// @Summary Деавторизация пользователя
// @Description Аннулирует токены пользователя
// @Tags auth
// @Security ApiKeyAuth
// @Produce json
// @Param Authorization header string  true "Access-токен"
// @Success 200 {string} string "Logged out"
// @Failure 401 {string} string "Unauthorized"
// @Router /logout [post]
func logout(db *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		guid, exists := c.Get("user_guid")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		_, err := db.Exec(context.Background(), `UPDATE refresh_tokens SET is_valid = false WHERE user_guid = $1`, guid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
	}
}

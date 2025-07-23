package config

import (
	"github.com/joho/godotenv"
	"os"
)

type Config struct {
	DatabaseURL string
	JWTSecret   string
	WebhookURL  string
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, err
	}

	return &Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		WebhookURL:  os.Getenv("WEBHOOK_URL"),
	}, nil
}

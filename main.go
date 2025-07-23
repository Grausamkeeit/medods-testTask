package main

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"log"
	docs "medods-task/docs"
	"medods-task/internal/api"
	"medods-task/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config: ", err)
	}

	dbpool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Unable to connect to database: ", err)
	}
	defer dbpool.Close()

	r := gin.Default()

	docs.SwaggerInfo.BasePath = "/"

	api.SetupRoutes(r, dbpool, cfg)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to run server: ", err)
	}

}

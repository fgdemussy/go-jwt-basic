package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"github.com/joho/godotenv"

	"jwt-todo/auth"
	"jwt-todo/handlers"
	"jwt-todo/middleware"
)

var router = gin.Default()
var redisClient *redis.Client
var authService *auth.Service
var tokenService *auth.Token
var handler handlers.Handler

func newRedisClient(dsn string) (*redis.Client, error) {
	redisClient = redis.NewClient(&redis.Options{
		Addr: dsn, //redis port
	})
	_, err := redisClient.Ping().Result()
	if err != nil {
		return nil, err
	}
	return redisClient, nil
}

func init() {
	env := os.Getenv("GO_JWT_ENV")
	if env == "" {
		env = "development"
	}
	godotenv.Load(".env." + env + ".local")
	if "test" != env {
		godotenv.Load(".env.local")
	}
	godotenv.Load(".env." + env)
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Failed loading .env with error: %v", err)
	}
	_, ok := os.LookupEnv("ACCESS_SECRET")
	if !ok {
		log.Fatalln("You need to define ACCESS_SECRET environment variable first.")
	}
	_, ok = os.LookupEnv("REFRESH_SECRET")
	if !ok {
		log.Fatalln("You need to define REFRESH_SECRET environment variable first.")
	}
	_, ok = os.LookupEnv("REDIS_DSN")
	if !ok {
		log.Fatalln("You need to define REDIS_DSN environment variable first.")
	}
}

func main() {
	redisClient, err := newRedisClient(os.Getenv("REDIS_DSN"))
	if err != nil {
		log.Fatalln("Redis service is unavailable")
	}
	authService = auth.NewService(redisClient)
	tokenService = auth.NewToken()
	handler := handlers.NewHandler(tokenService, authService)
	router.POST("/token/refresh", handler.Refresh)
	router.POST("/login", handler.Login)
	router.POST("/logout", middleware.TokenAuthMiddleware(), handler.Logout)
	router.POST("/todos", middleware.TokenAuthMiddleware(), handler.CreateTodo)
	log.Fatal(router.Run())
}

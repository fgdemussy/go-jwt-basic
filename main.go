package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"

	"jwt-todo/auth"
	"jwt-todo/handlers"
	"jwt-todo/middleware"
)

var router = gin.Default()
var redisClient *redis.Client
var authService *auth.Service
var tokenService *auth.Token
var handler handlers.Handler

func init() {
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
	dsn := "localhost:6379"
	redisClient = redis.NewClient(&redis.Options{
		Addr: dsn, //redis port
	})
	_, err := redisClient.Ping().Result()
	if err != nil {
		log.Fatalln("Redis service is unavailable")
	}
	authService = &auth.Service{
		Redis: redisClient,
	}
	handler := &handlers.Handler{Token: tokenService, Service: authService}
	router.POST("/token/refresh", handler.Refresh)
	router.POST("/login", handler.Login)
	router.POST("/logout", middleware.TokenAuthMiddleware(), handler.Logout)
	router.POST("/todos", middleware.TokenAuthMiddleware(), handler.CreateTodo)
	log.Fatal(router.Run())
}

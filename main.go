package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"

	"jwt-todo/auth"
	"jwt-todo/handlers"
	"jwt-todo/middleware"
)

var router = gin.Default()

type todo struct {
	UserID uint64 `json:"user_id"`
	Title  string `json:"title"`
}

var redisClient *redis.Client
var authService auth.Authable

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
		panic(err)
	}
	authService = &auth.Service{
		Redis: redisClient,
	}
	tokenService := &auth.Token{}
	handler := &handlers.Handler{tokenService, authService}
	router.POST("/token/refresh", handler.Refresh)
	router.POST("/login", handler.Login)
	router.POST("/logout", middleware.TokenAuthMiddleware(), logout)
	router.POST("/todos", middleware.TokenAuthMiddleware(), createTodo)
	log.Fatal(router.Run())
}

func createTodo(c *gin.Context) {
	var td *todo
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}
	tokenAuth, err := auth.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	userID, err := authService.Fetch(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	td.UserID = userID

	//you can proceed to save the Todo to a database
	//but we will just return it to the caller here:
	c.JSON(http.StatusCreated, td)
}

func logout(c *gin.Context) {
	accessDetails, err := auth.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}
	deleted, err := authService.Delete(accessDetails.AccessUUID)
	if err != nil || deleted == 0 {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	c.JSON(http.StatusOK, "successfully logged out")
}

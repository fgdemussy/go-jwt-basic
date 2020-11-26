package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"

	"jwt-todo/auth"
	"jwt-todo/middleware"
)

var router = gin.Default()

type user struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type todo struct {
	UserID uint64 `json:"user_id"`
	Title  string `json:"title"`
}

var u1 = &user{
	ID:       1,
	Username: "john",
	Password: "pass",
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
	dsn, ok := os.LookupEnv("REDIS_DSN")
	if !ok {
		dsn = "localhost:6379"
	}
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
}

func main() {
	router.POST("/token/refresh", refresh)
	router.POST("/login", login)
	router.POST("/logout", middleware.TokenAuthMiddleware(), logout)
	router.POST("/todos", middleware.TokenAuthMiddleware(), createTodo)
	log.Fatal(router.Run())
}

func login(c *gin.Context) {
	var u user
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Are you even providing credentials?")
		return
	}
	if u.Username != u1.Username || u.Password != u1.Password {
		c.JSON(http.StatusUnauthorized, "Please provide login credentials")
		return
	}
	token, err := auth.CreateToken(u1.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	err = authService.Create(u1.ID, token)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
	}
	tokens := &auth.Tokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
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

func refresh(c *gin.Context) {
	authService.Refresh(c)
}

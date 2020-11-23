package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
)

var router = gin.Default()

type user struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}
type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

var u1 = &user{
	ID:       1,
	Username: "john",
	Password: "pass",
}

func init() {
	_, ok := os.LookupEnv("ACCESS_SECRET")
	if !ok {
		log.Fatalln("You need to define ACCESS_SECRET environment variable first.")
	}
	var client *redis.Client
	//Initializing redis
	dsn, ok := os.LookupEnv("REDIS_DSN")
	if !ok {
		dsn = "localhost:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr: dsn, //redis port
	})
	_, err := client.Ping().Result()
	if err != nil {
		panic(err)
	}
}

func main() {
	router.POST("/login", login)
	log.Fatal(router.Run())
}

func login(c *gin.Context) {
	var u user
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err)
		return
	}
	if u.Username != u1.Username || u.Password != u1.Password {
		c.JSON(http.StatusUnauthorized, "Please provide login credentials")
		return
	}
	token, err := createToken(u1.ID, os.Getenv("ACCESS_SECRET"))
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	c.JSON(http.StatusOK, token)
}

func createToken(userID uint64, secret string) (string, error) {
	var err error
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userID
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return token, nil
}

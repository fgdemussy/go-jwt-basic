package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"github.com/twinj/uuid"
)

var router = gin.Default()

type user struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}
type tokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUUID   string
	RefreshUUID  string
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
	_, ok = os.LookupEnv("REFRESH_SECRET")
	if !ok {
		log.Fatalln("You need to define REFRESH_SECRET environment variable first.")
	}

	var client *redis.Client
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
	token, err := createToken(u1.ID, os.Getenv("ACCESS_SECRET"), os.Getenv("REFRESH_SECRET"))
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	c.JSON(http.StatusOK, token)
}

func createToken(userID uint64, accessSecret, refereshSecret string) (*tokenDetails, error) {
	td := &tokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUUID = uuid.NewV4().String()
	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUUID = uuid.NewV4().String()

	var err error
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUUID
	atClaims["user_id"] = userID
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	sat, err := at.SignedString([]byte(accessSecret))
	if err != nil {
		return nil, err
	}
	td.AccessToken = sat

	rtClaims := jwt.MapClaims{}
	rtClaims["exp"] = td.RtExpires
	rtClaims["refresh_uuid"] = td.RefreshUUID
	rtClaims["user_id"] = userID
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	srt, err := rt.SignedString([]byte(refereshSecret))
	if err != nil {
		return nil, err
	}
	td.RefreshToken = srt
	return td, nil
}

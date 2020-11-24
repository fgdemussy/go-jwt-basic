package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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

type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type tokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUUID   string
	RefreshUUID  string
	AtExpires    int64
	RtExpires    int64
}

type accessDetails struct {
	AccessUUID string
	UserID     uint64
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

var client *redis.Client

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
	router.POST("/logout", tokenAuthMiddleware(), logout)
	router.POST("/todos", tokenAuthMiddleware(), createTodo)
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
	token, err := createToken(u1.ID, os.Getenv("ACCESS_SECRET"), os.Getenv("REFRESH_SECRET"))
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	err = createAuth(u1.ID, token)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
	}
	tokens := &tokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
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

func createAuth(userID uint64, td *tokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := client.Set(td.AccessUUID, strconv.Itoa(int(userID)), at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := client.Set(td.RefreshUUID, strconv.Itoa(int(userID)), rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

func extractToken(r *http.Request) string {
	payload := r.Header.Get("Authorization")
	parts := strings.Split(payload, " ")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func verifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := extractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func tokenValid(r *http.Request) error {
	token, err := verifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

func extractTokenMetadata(r *http.Request) (*accessDetails, error) {
	token, err := verifyToken(r)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUUID, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userID, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &accessDetails{
			AccessUUID: accessUUID,
			UserID:     userID,
		}, nil
	}
	return nil, err
}

func fetchAuth(authD *accessDetails) (uint64, error) {
	userid, err := client.Get(authD.AccessUUID).Result()
	if err != nil {
		return 0, err
	}
	userID, _ := strconv.ParseUint(userid, 10, 64)
	return userID, nil
}

func createTodo(c *gin.Context) {
	var td *todo
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}
	tokenAuth, err := extractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	userID, err := fetchAuth(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	td.UserID = userID

	//you can proceed to save the Todo to a database
	//but we will just return it to the caller here:
	c.JSON(http.StatusCreated, td)
}

func deleteAuth(uuid string) (int64, error) {
	deleted, err := client.Unlink(uuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func logout(c *gin.Context) {
	accessDetails, err := extractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}
	deleted, err := deleteAuth(accessDetails.AccessUUID)
	if err != nil || deleted == 0 {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	c.JSON(http.StatusOK, "successfully logged out")
}

func tokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := tokenValid(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			c.Abort()
			return
		}
		c.Next()
	}
}

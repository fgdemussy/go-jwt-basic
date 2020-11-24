package auth

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
)

// AccessDetails data structure
type AccessDetails struct {
	AccessUUID string
	UserID     uint64
}

// TokenDetails data structure for tokens
type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUUID   string
	RefreshUUID  string
	AtExpires    int64
	RtExpires    int64
}

// Tokens data structure for token pair
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

var client *redis.Client

// CreateAuth persists userId under AccessUUID
func CreateAuth(userID uint64, td *TokenDetails) error {
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

// DeleteAuth deletes AccessUUID key in data store
func DeleteAuth(uuid string) (int64, error) {
	deleted, err := client.Unlink(uuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// FetchAuth restores UserID under AccessUUID in data store
func FetchAuth(authD *AccessDetails) (uint64, error) {
	userid, err := client.Get(authD.AccessUUID).Result()
	if err != nil {
		return 0, err
	}
	userID, _ := strconv.ParseUint(userid, 10, 64)
	return userID, nil
}

// Refresh validates refresh_token to provide a new token pair
func Refresh(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	refreshToken := mapToken["refresh_token"]
	token, err := jwt.Parse(refreshToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, "Refresh token expired")
		return
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, err)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		c.JSON(http.StatusUnauthorized, "refresh expired")
	}
	refreshUUID, ok := claims["refresh_uuid"].(string)
	if !ok {
		c.JSON(http.StatusUnprocessableEntity, "Error occurred")
		return
	}
	userID, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Error occurred")
		return
	}
	deleted, err := DeleteAuth(refreshUUID)
	if err != nil || deleted == 0 {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	ts, err := CreateToken(userID)
	if err != nil {
		c.JSON(http.StatusForbidden, err.Error())
		return
	}
	err = CreateAuth(userID, ts)
	if err != nil {
		c.JSON(http.StatusForbidden, err.Error())
		return
	}
	tokens := &Tokens{
		AccessToken:  ts.AccessToken,
		RefreshToken: ts.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

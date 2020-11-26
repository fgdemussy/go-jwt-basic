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

// Authable provides an interface to deal with required operations to manage AccessDetails in a datastore
type Authable interface {
	Creator
	Deletable
	Refreshable
	Fetchable
}

// Creator allows persistence in a datastore
type Creator interface {
	Create(uint64, *TokenDetails) error
}

// Deletable allows to destroy a record from the datastore
type Deletable interface {
	Delete(string) (int64, error)
}

// Fetchable allows to fetch a record from the datastore
type Fetchable interface {
	Fetch(*AccessDetails) (uint64, error)
}

// Refreshable allows to create a new token and save it to datastore
type Refreshable interface {
	Refresh(*gin.Context)
}

// AccessDetails data structure
type AccessDetails struct {
	AccessUUID string
	UserID     uint64
}

// Service implements Authable to provide AccessDetails persistence in a datastore
type Service struct {
	Redis *redis.Client
}

// Create persists userId under AccessUUID
func (s *Service) Create(userID uint64, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := s.Redis.Set(td.AccessUUID, strconv.Itoa(int(userID)), at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := s.Redis.Set(td.RefreshUUID, strconv.Itoa(int(userID)), rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

// Delete deletes AccessUUID key in data store
func (s *Service) Delete(uuid string) (int64, error) {
	deleted, err := s.Redis.Unlink(uuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// Fetch restores UserID under AccessUUID key in data store
func (s *Service) Fetch(authD *AccessDetails) (uint64, error) {
	userid, err := s.Redis.Get(authD.AccessUUID).Result()
	if err != nil {
		return 0, err
	}
	userID, _ := strconv.ParseUint(userid, 10, 64)
	return userID, nil
}

// Refresh validates refresh_token to provide a new token pair
func (s *Service) Refresh(c *gin.Context) {
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
	deleted, err := s.Delete(refreshUUID)
	if err != nil || deleted == 0 {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	ts, err := CreateToken(userID)
	if err != nil {
		c.JSON(http.StatusForbidden, err.Error())
		return
	}
	err = s.Create(userID, ts)
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

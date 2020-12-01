package auth

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
)

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

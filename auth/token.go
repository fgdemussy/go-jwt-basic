package auth

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/twinj/uuid"
)

// Tokenizer allows token management and validation
type Tokenizer interface {
	CreateToken(uint64) (*TokenDetails, error)
	ExtractTokenMetadata(*http.Request) (*AccessDetails, error)
}

// Token implements Tokenizer
type Token struct{}

// NewToken returns a new Token
func NewToken() *Token {
	return new(Token)
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

// CreateToken generates access and refresh token pairs
func (t *Token) CreateToken(userID uint64) (*TokenDetails, error) {
	td := &TokenDetails{}
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
	sat, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	td.AccessToken = sat

	rtClaims := jwt.MapClaims{}
	rtClaims["exp"] = td.RtExpires
	rtClaims["refresh_uuid"] = td.RefreshUUID
	rtClaims["user_id"] = userID
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	srt, err := rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	td.RefreshToken = srt
	return td, nil
}

// ExtractTokenMetadata extracts AccessUUID and UserID from token payload
func (t *Token) ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := verify(r)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}
	accessUUID, ok := claims["access_uuid"].(string)
	if !ok {
		return nil, err
	}
	userID, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
	if err != nil {
		return nil, err
	}
	return &AccessDetails{
		AccessUUID: accessUUID,
		UserID:     userID,
	}, nil
}

// Valid validates wether a request has a valid authorization token
func Valid(r *http.Request) error {
	token, err := verify(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

func extract(r *http.Request) string {
	payload := r.Header.Get("Authorization")
	parts := strings.Split(payload, " ")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func verify(r *http.Request) (*jwt.Token, error) {
	tokenString := extract(r)
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

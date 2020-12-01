package handlers

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	"jwt-todo/auth"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type todo struct {
	UserID uint64 `json:"user_id"`
	Title  string `json:"title"`
}

type user struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var u1 = &user{
	ID:       1,
	Username: "john",
	Password: "pass",
}

// Handler resolves endpoints enabling token auth
type Handler struct {
	Token   *auth.Token
	Service *auth.Service
}

// NewHandler returns a handler with proper token auth & persistence
func NewHandler(t *auth.Token, s *auth.Service) *Handler {
	return &Handler{Token: t, Service: s}
}

// Login validates user credentials against data store and returns a token
func (h *Handler) Login(c *gin.Context) {
	var u user
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Are you even providing credentials?")
		return
	}
	if u.Username != u1.Username || u.Password != u1.Password {
		c.JSON(http.StatusUnauthorized, "Please provide login credentials")
		return
	}
	token, err := h.Token.CreateToken(u1.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	err = h.Service.Create(u1.ID, token)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
	}
	tokens := &auth.Tokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

// Refresh validates refresh_token to provide a new token pair
func (h *Handler) Refresh(c *gin.Context) {
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
	deleted, err := h.Service.Delete(refreshUUID)
	if err != nil || deleted == 0 {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	ts, err := h.Token.CreateToken(userID)
	if err != nil {
		c.JSON(http.StatusForbidden, err.Error())
		return
	}
	err = h.Service.Create(userID, ts)
	if err != nil {
		c.JSON(http.StatusForbidden, err.Error())
		return
	}
	tokens := &auth.Tokens{
		AccessToken:  ts.AccessToken,
		RefreshToken: ts.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

func (h *Handler) CreateTodo(c *gin.Context) {
	var td *todo
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}
	tokenAuth, err := h.Token.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	userID, err := h.Service.Fetch(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	td.UserID = userID

	//you can proceed to save the Todo to a database
	//but we will just return it to the caller here:
	c.JSON(http.StatusCreated, td)
}

func (h *Handler) Logout(c *gin.Context) {
	accessDetails, err := h.Token.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}
	deleted, err := h.Service.Delete(accessDetails.AccessUUID)
	if err != nil || deleted == 0 {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	c.JSON(http.StatusOK, "successfully logged out")
}

package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

var router = gin.Default()

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

	c.JSON(http.StatusOK, u)
}

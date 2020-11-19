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
	log.Fatal(router.Run(":8080"))
}

func login(c *gin.Context) {
	c.JSON(http.StatusOK, "hey")
}

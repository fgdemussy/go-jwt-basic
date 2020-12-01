package middleware

import (
	"net/http"

	"jwt-todo/auth"

	"github.com/gin-gonic/gin"
)

// TokenAuthMiddleware protects any given request route through jwt authorization
func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := auth.Valid(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			c.Abort()
			return
		}
		c.Next()
	}
}

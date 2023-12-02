package middleware

import (
	"fmt"
	"jwt-auth/internal/connections"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAuth(c *gin.Context) {

	// Get the cookie off request
	tokenString, err := c.Cookie("Authorization")
	if err != nil {
		// c.AbortWithStatus(http.StatusUnauthorized)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized, token is not found",
		})
	}

	// Decode/Validate it
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		// c.AbortWithStatus(http.StatusUnauthorized)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized, token is not valid",
		})
	}

	// Check the expiration
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			// c.AbortWithStatus(http.StatusUnauthorized)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "token expired",
			})
		}
	}

	raw := token.Claims.(jwt.MapClaims)["email"]

	// Find user by email in ldap

	user, isAdmin, _ := connections.IpaConnetion.CheckUser(raw.(string))
	// Attach to req

	//
	ok := strings.Contains(raw.(string), *user)
	if ok {
		c.Set(("user"), user)
		c.Set("isAdmin", isAdmin)
	}

	// Add user to context
	if tokenString != "" {
		c.Next()

	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

}

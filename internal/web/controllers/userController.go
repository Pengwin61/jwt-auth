package controllers

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var body struct {
	Email    string
	Password string
}

type person struct {
	Email    string
	password string
}

var persons = make([]person, 0)

func Singup(c *gin.Context) {

	// Get the email and password from the request body
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	// Add the user to the database
	tmp := person{
		Email:    body.Email,
		password: string(hash),
	}
	persons = append(persons, tmp)

	// Return a success message
	c.JSON(http.StatusOK, gin.H{
		"message": "User created successfully",
	})

}

func Login(c *gin.Context) {

	if len(persons) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Users list is empty",
		})
		return
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
	}

	if persons == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User not found",
		})
	}
	err := bcrypt.CompareHashAndPassword([]byte(persons[0].password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid password",
		})
		return
	}

	// Generate a jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": persons[0].Email,
		"exp":   time.Now().Add(time.Hour * 72).Unix(),
	})

	//
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to generate token",
		})
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600, "", "", false, true)
}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}

func Result(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"persons": persons,
	})
}

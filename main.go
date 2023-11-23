package main

import (
	"jwt-auth/internal/configs"
	"jwt-auth/internal/web/controllers"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {

	configs.InitConfigs()

	r := gin.Default()

	r.POST("/signup", controllers.Singup)
	r.GET("/result", controllers.Result)
	r.POST("/login", controllers.Login)

	err := r.Run(":" + os.Getenv("PORT"))
	if err != nil {
		return
	}
}

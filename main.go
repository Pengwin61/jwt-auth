package main

import (
	"jwt-auth/internal/configs"
	"jwt-auth/internal/connections"
	"jwt-auth/internal/web/controllers"
	"jwt-auth/internal/web/middleware"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {

	configs.InitConfigs()

	connections.IPAClient()

	r := gin.Default()

	r.POST("/signup", controllers.Singup)
	r.GET("/result", controllers.Result)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)

	err := r.Run(":" + os.Getenv("PORT"))
	if err != nil {
		return
	}
}

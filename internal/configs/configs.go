package configs

import (
	"log"

	"github.com/joho/godotenv"
)

func InitConfigs() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

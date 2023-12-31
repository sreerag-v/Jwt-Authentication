package database

import (
	"fmt"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var Db *gorm.DB

func InitDB() *gorm.DB {
	Db = connectDB()
	return Db
}

func connectDB() *gorm.DB {
	db_URL := os.Getenv("DNS")
	db, err := gorm.Open(postgres.Open(db_URL), &gorm.Config{})
	if err != nil {
		log.Panic("Failed to connect DATABASE")
	}
	fmt.Println("\nConnected to DATABASE: ", db.Name())
	return db
}

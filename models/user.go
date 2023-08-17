package models

import "gorm.io/gorm"

// This struct 'User' acts as a middle layer b/w the
// go programme and the database. Database understand json and
// go doesn't understand json it understands strings or those types of 
// data types. So you need to convert things from json to golang and 
// golang to json. Thats why you have this kind of struct here(to convert).
type User struct {
	gorm.Model
	Username string  //`gorm:"unique"`    // For unique username
	Password string
}

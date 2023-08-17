package routes

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"project_login/database"
	"project_login/helpers"
	"project_login/models"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var Store = sessions.NewCookieStore([]byte("secret")) // Is created to manage session data using cookie-based storage.

// The users struct is defined to represent user information with fields for ID, Username and Password
type Users struct {
	ID       int
	Username string
	Password string
}

// The HashPassword function takes a plain-text password as input and uses bcrypt to hash it with a cost factor of 14.
// The hashed password is then returned as a string.
func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic("Failled to create hash")
	}
	return string(bytes)
}

// The verifyPassword function compares a user-provided password with a stored hashed password to determine if they match.
// It returns a boolean indicating whether the passwords match.
func VerifyPassword(userPassword string, providedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	if err != nil {
		check = false
	}
	return check

}

func Login(c *gin.Context) {
	// This sets the "cache-control" header in http response to specify the response should not be cached by any client or any
	// intermidiat cache proxies. To ensure that the login page should be retrived from the server raher than any caches.
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	// This function is used to check if the user is already logged in, if yes then redirect to home page otherwise to login page
	ok := UserLoged(c)
	if ok {
		c.Redirect(303, "/home")
		return
	}
	c.HTML(http.StatusOK, "login.html", nil)

	//This code ensures that the login page is not cached and if the user already logged in redirect to home page or render the login page
}

// PostLogin Handles the POST request when a user submits the login form. It validates the username and password,
// generates a token using the GenerateTokens function from the helpers package, and sets the token in the session.
func PostLogin(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	var user []Users
	var status bool
	Fusername := c.Request.FormValue("username") //Getting username from user
	Fpassword := c.Request.FormValue("password")

	db := database.InitDB() //This command is to initilize connection to database
	db.Find(&user)          // To fetch all user records to variable user from database

	// This is to iterate all the user passwords in the user variable.(i.password indicates that password in each iteration)
	for _, i := range user {
		passwordIsValid := VerifyPassword(Fpassword, i.Password) // Fpassword and i.password are sent to func Verify password and a bool will be returned to passwordIsValid
		if i.Username == Fusername && passwordIsValid {          // If i.uername == Fusername && passwordIsValid is true then,
			status = true // Set status to true and break the loop.
			break
		}
	}

	if !status { // If not true then show a message to user and redirect user to login page
		log.Println("Wrong Username or Password\n\t\tTry Again")
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	token, _, _ := helpers.GenerateTokens(Fusername, "User") // This function is for generate tokens for the user and returned token will be saved into token
	session, _ := Store.Get(c.Request, "jwt_token")
	session.Values["token"] = token
	session.Save(c.Request, c.Writer)
	c.Redirect(http.StatusSeeOther, "/home")
}

func Signup(c *gin.Context) {
	c.HTML(http.StatusOK, "signup.html", nil)
}

func PostSignup(c *gin.Context) {
	var user []Users
	var status bool = true
	FusernameN := c.Request.FormValue("username")
	Fpassword := HashPassword(c.Request.FormValue("password"))

	db := database.InitDB()
	db.AutoMigrate(&Users{})
	db.Find(&user)

	for _, i := range user {
		if i.Username == FusernameN {
			status = false
			break
		}
	}

	if !status {
		log.Printf("hello %s , The username is already taken", FusernameN)
		c.Redirect(303, "/signup")
		return

	}

	db.Create(&Users{Username: FusernameN, Password: Fpassword})
	log.Printf("Hey %s, Your account is successfully created.", FusernameN)
	c.Redirect(http.StatusSeeOther, "/login")

}

func Admin(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	ok := AdminLoged(c)
	if ok {
		c.Redirect(303, "/wadmin")
		return
	}
	c.HTML(http.StatusOK, "admin.html", nil)
}

func PostAdmin(c *gin.Context) {

	config := &models.Admin{
		UserName: os.Getenv("ADMIN_NAME"),
		Password: HashPassword(os.Getenv("PASSWORD")),
	}

	config.Password = HashPassword(config.Password)

	Fusername := c.Request.FormValue("username")
	Fpassword := c.Request.FormValue("password")

	passwordIsValid := VerifyPassword(Fpassword, config.Password)

	if Fusername != config.UserName || passwordIsValid {
		log.Println("Wrong Username or Password , Check Again!")
		c.Redirect(303, "/admin")
		return
	}

	token, _, _ := helpers.GenerateTokens(Fusername, "Admin")

	session, _ := Store.Get(c.Request, "admin_jwt_token")
	session.Values["token"] = token
	session.Save(c.Request, c.Writer)
	c.Redirect(http.StatusSeeOther, "/home")

	c.Redirect(303, "/wadmin")

}

func Wadmin(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	var user []Users

	ok := AdminLoged(c)
	if !ok {
		c.Redirect(303, "/admin")
		return
	}

	db := database.InitDB()
	var us = [11]string{}

	var id = [11]int{}
	db.Raw("SELECT id,username FROM users").Scan(&user)
	for ind, i := range user {
		us[ind], id[ind] = i.Username, i.ID

	}

	c.HTML(http.StatusOK, "welcomeadmin.html", gin.H{

		"users": us,
		"id":    id,
	})
}

func Home(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	ok := UserLoged(c)
	if !ok {
		c.Redirect(303, "/login")
		return
	}
	c.HTML(http.StatusOK, "welcomeuser.html", gin.H{
		"message": ".Fusername",
	})

}

func Logout(c *gin.Context) {

	cookie, err := c.Request.Cookie("jwt_token")
	if err != nil {
		c.Redirect(303, "/login")
	}
	c.SetCookie("jwt_token", "", -1, "/", "localhost", false, false)
	_ = cookie
	c.Redirect(http.StatusSeeOther, "/login")
}

func DeleteUser(c *gin.Context) {
	var user Users
	name := c.Param("name")
	db := database.InitDB()
	db.Where("username=?", name).Delete(&user)
	c.Redirect(303, "/wadmin")

}

func UpdateUser(c *gin.Context) {

	updateData := c.Request.FormValue("updatedata")
	var user Users
	name := c.Param("name")
	db := database.InitDB()
	db.Model(&user).Where("username=?", name).Update("username", updateData)
	c.Redirect(303, "/wadmin")
}

func CreateUser(c *gin.Context) {
	var user []Users
	var status bool = true

	FusernameN := c.Request.FormValue("username")
	Fpassword := HashPassword(c.Request.FormValue("password"))

	//database things
	db := database.InitDB()
	db.AutoMigrate(&Users{})
	db.Find(&user)

	for _, i := range user {
		if i.Username == FusernameN {
			status = false
			break
		}
	}

	if !status {
		log.Println("hello Admin , The username is already in Use")
		c.Redirect(303, "/wadmin")
		return

	}

	db.Create(&Users{Username: FusernameN, Password: Fpassword})
	log.Println("Hey Admin, Account is successfully created.")
	c.Redirect(http.StatusSeeOther, "/wadmin")

}

func IndexHandler(c *gin.Context) {
	session, _ := Store.Get(c.Request, "jwt_token")
	_, ok := session.Values["token"]
	if !ok {
		c.Redirect(303, "/login")
		return
	}
	c.Redirect(303, "/home")
}

func AdminLoged(c *gin.Context) bool {
	session, _ := Store.Get(c.Request, "admin_jwt_token")
	token, ok := session.Values["token"]
	fmt.Println(token)
	if !ok {
		return ok
	}
	return true
}

func UserLoged(c *gin.Context) bool {

	session, _ := Store.Get(c.Request, "jwt_token")
	token, ok := session.Values["token"]
	fmt.Println(token)
	if !ok {

		return ok
	}
	return true

}

func LogoutAdmin(c *gin.Context) {

	cookie, err := c.Request.Cookie("admin_jwt_token")
	if err != nil {
		c.Redirect(303, "/admin")
	}
	c.SetCookie("admin_jwt_token", "", -1, "/", "localhost", false, false)
	_ = cookie
	c.Redirect(http.StatusSeeOther, "/admin")
}

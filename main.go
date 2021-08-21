package main

import (
	//"reflect"
	"context"
	"fmt"
	"time"

	//web libs
	"net/http"
	//en-/de-coding libs
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	//regex
	"regexp"
	//rng
	"math/rand"
	//db
	"go.mongodb.org/mongo-driver/bson"
)

//____________________________________SECURITY GUIDELINES____________________________________
//Database injection preventions:                                                           |
//  - Usernames and emails stored as base64 strings                                         |
//  - Passwords hashed server-side before storing                                           |
//General Security practices                                                                |
//  - User data stored in aes encryption                                                    |
//      - Key is derived from DIFFERENT hashing algorithm(sha 256) than auth-hash(sha 512)  |
//  - NEVER STORE UNSALTED HASHES OR PLAINTEXT CREDENTIALS                                  |
//-------------------------------------------------------------------------------------------

func createUser(w http.ResponseWriter, req *http.Request) {
	//TAKES: User name, mail, pwhash
	//RESPONDS: Status code

	//check that request method is actually post
	if req.Method != http.MethodPost {
		statusResponse(w, "Invalid request method!", 400)
		return
	}
	if !checkForJsonHeader(w, req) {
		return
	}

	//Struct for decoding json
	type user struct {
		Name   string
		Mail   string
		PwHash string
	}

	var usr user
	//decode json
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&usr)

	if decodeErr != nil {
		statusResponse(w, "Invalid Json", 500)
		return
	}
	//check if required data is included in json
	if usr.Name == "" || usr.Mail == "" || usr.PwHash == "" {
		statusResponse(w, "Invalid Json", 500)
		return
	}

	//Da email regex validation
	pattern := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	matches := pattern.MatchString(usr.Mail)
	if !matches {
		statusResponse(w, "Invalid Email", 500)
		return
	}

	//Encode username and email to base64
	base64Mail := base64.URLEncoding.EncodeToString([]byte(usr.Mail))
	base64Name := base64.URLEncoding.EncodeToString([]byte(usr.Name))

	//Struct for writing/reading all relevant data to/from mongodb
	type dbUser struct {
		B64Name      string
		B64Mail      string
		Salt         string
		Hash         string
		UsrID        string
		CreationTime string
		TodoAmnt     int
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	//Check for duplicate email and uname
	var usrRes dbUser

	//Check for duplicate email
	type mfilter struct{ B64Mail string }
	mailFilter := mfilter{base64Mail}
	readerr := userDataCollection.FindOne(ctx, mailFilter).Decode(&usrRes)
	if readerr == nil {
		statusResponse(w, "Duplicate email", 400)
		return
	}

	//Check for duplicate username
	type nfilter struct{ B64Name string }
	nameFilter := nfilter{base64Name}
	readerr = userDataCollection.FindOne(ctx, nameFilter).Decode(&usrRes)
	if readerr == nil {
		statusResponse(w, "Duplicate Username", 400)
		return
	}

	//generate salt and generate sha512 hash of usr.PwHash, encode salt to base64
	salt := generateRandomSalt(config.SaltSize)
	hexSalt := hex.EncodeToString(salt)
	hash := hash(usr.PwHash, salt)

	var chosen = false
	var usrID string

	//generate random user id
	for !chosen {
		usrID = randomString(config.UserIDLength)
		//Check for id in database
		type idfilter struct{ Usrid string }
		idFilter := idfilter{usrID}
		readerr = userDataCollection.FindOne(ctx, idFilter).Decode(&usrRes)
		//End loop if userid is not duplicate
		if readerr != nil {
			chosen = true
		}
	}

	//Get time of account creation
	dt := time.Now()
	creationTime := dt.Format("01-02-2006 15:04:05")

	//Data to write to mongodb
	usrData := dbUser{base64Name, base64Mail, hexSalt, hash, usrID, creationTime, 0}

	//Insert user into db
	_, err := userDataCollection.InsertOne(context.TODO(), usrData)
	if err != nil {
		fmt.Println(err)
		statusResponse(w, "Internal server error!", 500)
		return
	}

	fmt.Println("New user registered!")
	statusResponse(w, "success!", 200)
}

func removeUser(w http.ResponseWriter, req *http.Request) {
	//TAKES: User credentials
	//RESPONDS: Status code
	if req.Method != http.MethodDelete {
		statusResponse(w, "Invalid request method!", 400)
		return
	}
	if !checkForJsonHeader(w, req) {
		return
	}

	type request struct {
		UsrId  string `json:"usrid"`
		PwHash string `json:"pwhash"`
	}

	var rq request

	//decode json from body
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	parseErr := decoder.Decode(&rq)

	if parseErr != nil {
		fmt.Println(parseErr)
		statusResponse(w, "Invalid Json", 400)
		return
	}
	if rq.UsrId == "" || rq.PwHash == "" {
		statusResponse(w, "Invalid Json", 400)
		return
	}

	//VALIDATE USER LOGIN
	if !validatePw(rq.UsrId, rq.PwHash) {
		statusResponse(w, "Invalid Login!", 400)
		return
	}

	//DELETE USER AND THEIR NOTES FROM DB
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	_, e := userDataCollection.DeleteMany(ctx, bson.M{"usrid": rq.UsrId})

	_, e = todoCollection.DeleteMany(ctx, bson.M{"ownerid": rq.UsrId})

	if e != nil {
		statusResponse(w, "Internal Server Error!", 500)
		return
	}

	statusResponse(w, "success!", 200)
}

func validateLogin(w http.ResponseWriter, req *http.Request) {
	//TAKES: email, pwhash
	//RESPONDS: Status code, userid
	if req.Method != http.MethodGet {
		statusResponse(w, "Invalid request method!", 400)
		return
	}
	if !checkForJsonHeader(w, req) {
		return
	}

	type request struct {
		Mail   string `json:"mail"`
		PwHash string `json:"pwhash"`
	}

	var rq request

	//decode json from body
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	parseErr := decoder.Decode(&rq)

	if parseErr != nil {
		statusResponse(w, "Invalid Json", 500)
		return
	}

	//GET USERID FORM DB
	type dbContent struct {
		Usrid string `json:"usrid"`
		Hash  string `json:"hash"`
	}

	var content dbContent

	filter := bson.D{{"b64mail", base64.URLEncoding.EncodeToString([]byte(rq.Mail))}}

	//search for user id and parse content of db to object
	e := userDataCollection.FindOne(context.TODO(), filter).Decode(&content)
	if e != nil {
		statusResponse(w, "User Does Not Exist!", 400)
		return
	}

	//VALIDATE USER LOGIN
	if !validatePw(content.Usrid, rq.PwHash) {
		statusResponse(w, "Invalid Login!", 400)
		return
	}

	//Respond code 200 and user id
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	resp := make(map[string]string)
	resp["usrid"] = content.Usrid
	jsonResp, _ := json.Marshal(resp)
	w.Write(jsonResp)
}

func createToDo(w http.ResponseWriter, req *http.Request) {
	//TAKES: User credentials, title and body of todo
	//RESPONDS: Status code
	if req.Method != http.MethodPost {
		statusResponse(w, "Invalid request method!", 400)
		return
	}
	if !checkForJsonHeader(w, req) {
		return
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	//Struct for parsing requet json
	type request struct {
		UsrId   string `json:"usrid"`
		PwHash  string `json:"pwhash"`
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	var td request
	//decode json from body
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	parseErr := decoder.Decode(&td)

	if parseErr != nil {
		fmt.Println(parseErr)
		statusResponse(w, "Invalid Json", 400)
		return
	}
	//check if required data is included in json
	if td.UsrId == "" || td.PwHash == "" || td.Title == "" || td.Content == "" {
		statusResponse(w, "Invalid Json", 400)
		return
	}

	//Check if user creds are valid
	if !validatePw(td.UsrId, td.PwHash) {
		statusResponse(w, "Invalid Login!", 400)
		return
	}

	//GET ToDo NUMBER, VERIFY NOT TOO MANY ToDos WERE CREATED

	//get current todo amnt from db
	filter := bson.D{{"usrid", td.UsrId}}
	type tdAmntFilter struct{ Todoamnt int }
	var taf tdAmntFilter
	e := userDataCollection.FindOne(ctx, filter).Decode(&taf)

	if taf.Todoamnt >= config.MaxTodoAmt {
		statusResponse(w, "Maximum Amount Of Todos Exceeded!", 400)
		return
	}

	fmt.Println(taf.Todoamnt)

	//increase todo amnt in db by 1
	update := bson.D{
		{"$set", bson.D{
			{"todoamnt", taf.Todoamnt + 1},
		}},
	}

	_, e = userDataCollection.UpdateOne(ctx, filter, update)
	if e != nil {
		statusResponse(w, "Internal Server Error!", 500)
	}

	//GENERATE 32-BIT ENCRYPTION KEY USING UNSALTED SHA256, ENCRYPT USING AES
	encKey := unsaltedSha256Hash(td.PwHash)
	encTitle := encryptAES(td.Title, encKey)
	encContent := encryptAES(td.Content, encKey)

	//Struct for storing entry to database
	type todoEntry struct {
		Title        string
		Content      string
		OwnerID      string
		CreationTime string
		TodoID       string
		Done         bool
	}

	//Get time of creation as a string
	dt := time.Now()
	creationTime := dt.Format("01-02-2006 15:04:05")

	//generate random user id
	var chosen = false
	var todoID string

	//Repeat gen process until not duplicate
	for !chosen {
		todoID = randomString(config.TodoIDLength)
		//Check for id in database
		type idfilter struct{ TodoId string }
		idFilter := idfilter{todoID}
		readerr := todoCollection.FindOne(ctx, idFilter) //.Decode(&usrRes)
		//End loop if userid is not duplicate (if read error occurs)
		if readerr != nil {
			chosen = true
		}
	}

	todo := todoEntry{encTitle, encContent, td.UsrId, creationTime, todoID, false}

	//Add todo to database
	_, err := todoCollection.InsertOne(ctx, todo)
	if err != nil {
		fmt.Println(err)
		statusResponse(w, "Internal server error!", 500)
		return
	}

	fmt.Println("User " + td.UsrId + " created a todo!")
	statusResponse(w, "success!", 200)
}

func removeToDo(w http.ResponseWriter, req *http.Request) {
	//TAKES: User credentials, todo id
	//RESPONDS: Status code
	if req.Method != http.MethodDelete {
		statusResponse(w, "Invalid request method!", 400)
		return
	}
	if !checkForJsonHeader(w, req) {
		return
	}

	type request struct {
		UsrId  string `json:"usrid"`
		PwHash string `json:"pwhash"`
		TodoID string `json:"todoid"`
	}

	var rq request

	//decode json from body
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	parseErr := decoder.Decode(&rq)

	if parseErr != nil {
		fmt.Println(parseErr)
		statusResponse(w, "Invalid Json", 400)
		return
	}

	if rq.UsrId == "" || rq.PwHash == "" || rq.TodoID == "" {
		statusResponse(w, "Invalid Json", 400)
		return
	}

	//VALIDATE USER LOGIN
	if !validatePw(rq.UsrId, rq.PwHash) {
		statusResponse(w, "Invalid Login!", 400)
		return
	}

	//Check if user owns todo
	type todoRes struct {
		Ownerid string `json:"ownerid"`
	}
	var tdRes todoRes

	filter := bson.D{{"todoid", rq.TodoID}}

	fmt.Println(filter)

	e := todoCollection.FindOne(context.TODO(), filter).Decode(&tdRes)
	if e != nil {
		statusResponse(w, "Todo Does Not Exist!", 404)
		return
	}

	fmt.Println(rq.UsrId + " " + tdRes.Ownerid)

	if rq.UsrId != tdRes.Ownerid {
		statusResponse(w, "You Do Not Own That Todo!", 403)
		return
	}

	//DELETE ToDo FROM DB

	_, e = todoCollection.DeleteOne(context.TODO(), filter)
	if e != nil {
		statusResponse(w, "Internal Server Error!", 500)
		return
	}

	statusResponse(w, "success!", 200)
}

func getToDos(w http.ResponseWriter, req *http.Request) {
	//TAKES: Ammount of todos to display, user credentials
	//RESPONDS: Specified ammount of todos(todo title, body and state(done/not done))
	if !checkForJsonHeader(w, req) {
		return
	}

	//TODO VALIDATE USER LOGIN, GET ToDo DATA FROM DB, GENERATE 32-BIT ENCRYPTION KEY USING UNSALTED SHA256, DECRYPT DATA, RESPOND DATA AS JSON
}

func validatePw(usrid string, pwhash string) bool {

	filter := bson.D{{"usrid", usrid}}

	type dbContent struct {
		Salt string `json:"salt"`
		Hash string `json:"hash"`
	}

	var content dbContent

	//search for user id and parse content of db to object
	e := userDataCollection.FindOne(context.TODO(), filter).Decode(&content)
	if e != nil {
		return false
	}

	fmt.Println(content.Salt)
	//hash inputted data with salt from db
	originalStringBytes, err := hex.DecodeString(content.Salt)
	if err != nil {
		return false
	}

	fmt.Println(usrid + " " + pwhash + " " + content.Salt + " " + content.Hash)

	hashedInHash := hash(pwhash, originalStringBytes)

	if hashedInHash == content.Hash {
		return true
	}

	return false
}

func checkForJsonHeader(w http.ResponseWriter, req *http.Request) bool {
	//Validate that content type header is set to application/json
	headerContentTtype := req.Header.Get("Content-Type")
	if headerContentTtype != "application/json" {
		statusResponse(w, "Content Type is not application/json", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

//Helper function to send status code and message
func statusResponse(w http.ResponseWriter, message string, httpStatusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	resp := make(map[string]string)
	resp["message"] = message
	jsonResp, _ := json.Marshal(resp)
	w.Write(jsonResp)
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {

	readConfig()
	connectToDb()

	http.HandleFunc("/createUser", createUser)
	http.HandleFunc("/removeUser", removeUser)
	http.HandleFunc("/validateLogin", validateLogin)
	http.HandleFunc("/createToDo", createToDo)
	http.HandleFunc("/removeToDo", removeToDo)
	http.HandleFunc("/getToDos", getToDos)

	http.ListenAndServe(":8090", nil)
}

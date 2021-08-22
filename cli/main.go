package main

import(
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"net/http"
	"encoding/json"
	"bytes"
	"crypto/sha512"
	"encoding/base64"
)

var baseUrl string = "http://127.0.0.1:8090"

var loggedInId string;
var loggedInHash string;

func main(){
	fmt.Println("Todo App")
	fmt.Println("---------------------")

	for true {
		
		switch usrInput("->") {
			case "help":
				fmt.Println("to create an account type \"signup\"\nto log in type \"login\"")
			case "clear":
				c := exec.Command("clear")
				c.Stdout = os.Stdout
				c.Run()
			case "signup":

				mail := usrInput("Mail: ")
				name := usrInput("Name: ")
				password := usrInput("Password: ")

				var jsonData = []byte(`{
					"name": "`+name+`",
					"mail": "`+mail+`",
					"pwhash": "`+hash(password)+`"
				}`)

				res := httpPost(baseUrl+"/createUser", jsonData)

				fmt.Println(res.Message)

			case "login":
				mail := usrInput("Mail: ")
				password := usrInput("Password: ")

				hash := hash(password)

				var jsonData = []byte(`{
					"mail": "`+mail+`",
					"pwhash": "`+hash+`"
				}`)

				res := httpPost(baseUrl+"/validateLogin", jsonData)

				if(res.Message == "" && res.UsrID != ""){ 
					loggedInHash = hash
					loggedInId = res.UsrID
					fmt.Println("You are now logged in.")
				}else{
					fmt.Println(res.Message)
				}
			case "create":
				if loggedInId == "" {fmt.Println("Please log in first."); break}
				title := usrInput("Title: ")
				content := usrInput("Content: ")

				var jsonData = []byte(`{
					"usrid": "`+loggedInId+`",
					"pwhash": "`+loggedInHash+`",
					"title": "`+title+`",
					"content": "`+content+`"
				}`)

				res := httpPost(baseUrl+"/createToDo", jsonData)

				fmt.Println(res.Message)

			default:
				fmt.Println("Invalid command!")
		}
	}
}

func usrInput(prompt string) string{
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
    // convert CRLF to LF
    return strings.Replace(text, "\n", "", -1)
}

type response struct{
	Message string
	UsrID string
}

func httpPost(url string, data []byte) response {
	hc := http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	req.Header.Add("Content-Type", "application/json")

	resp, err := hc.Do(req)

	checkError(err)
	defer resp.Body.Close()

	var res response

    json.NewDecoder(resp.Body).Decode(&res)

	if(res.Message == "" && res.UsrID == ""){fmt.Println( "ERROR: Server did not respond correctly");}

	return res
}

func checkError(err error){
	if err != nil {fmt.Println(err); os.Exit(1)}
}

//Hash data with sha512
func hash(data string) string {

	var originalBytes = []byte(data)
	var sha512Hasher = sha512.New()
  
	sha512Hasher.Write(originalBytes)
	var hashedBytes = sha512Hasher.Sum(nil)
  
	// Convert the hashed password to a base64 encoded string
	var base64EncodedHash = base64.URLEncoding.EncodeToString(hashedBytes)
	return base64EncodedHash
}
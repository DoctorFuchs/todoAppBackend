package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type cfg struct {
	SaltSize               int
	UserIDLength           int
	TodoIDLength           int
	DbUri                  string
	DbName                 string
	UserDataCollectionName string
	TodoCollectionName     string
	MaxTodoAmt             int
}

var config cfg

func readConfig() {
	if !readConfigFromFile("./config/config.json") {
		fmt.Println("Could not read config, attempting to read default config file...")
		if readConfigFromFile("./config/config.default.json") {
			fmt.Println("Success!")
		} else {
			fmt.Println("Could not read config, quitting...")
			os.Exit(1)
		}
	}
	if config.DbUri == "backend_net.database.ip4" {
		ip := os.Getenv("IP")
		ips := strings.Split(ip, ".")
		config.DbUri = strings.Join(ips[0:2], ".")+"2"
	}
	fmt.Println("Successfully read config file")
}

func readConfigFromFile(filename string) bool {
	file, err := os.Open(filename)
	if err != nil {
		return false
	}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return false
	}
	return true
}

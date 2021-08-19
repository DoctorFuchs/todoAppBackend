package main

import(
    "context"
    "log"
    "fmt"
    "time"
    //"go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    //"go.mongodb.org/mongo-driver/mongo/readpref"
)

var userDataCollection *mongo.Collection
var todoCollection *mongo.Collection

func connectToDb(){

    // Set client options
    clientOptions := options.Client().ApplyURI(string(config.DbUri))

    // Connect to MongoDB
    client, err := mongo.Connect(context.TODO(), clientOptions)

    ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

    // Check the connection
    err = client.Ping(ctx, nil)

    if err != nil {
        log.Fatal(err)
    }

    db := client.Database(config.DbName)
    userDataCollection = db.Collection(config.UserDataCollectionName)
    todoCollection = db.Collection(config.TodoCollectionName)

    fmt.Println("Connected to MongoDB!")
}

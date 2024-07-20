package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/joho/godotenv"
	"google.golang.org/grpc"

	"github.com/isaacwassouf/cryptography-service/database"
	pb "github.com/isaacwassouf/cryptography-service/protobufs/cryptography_service"
)

type CryptographyServiceManager struct {
	pb.UnimplementedCryptographyManagerServer
	cryptographyServiceDB *database.CryptographyServiceDB
}

func (s *CryptographyServiceManager) Encrypt(ctx context.Context, in *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	return &pb.EncryptResponse{Ciphertext: "EncryptedData"}, nil
}

func (s *CryptographyServiceManager) Decrypt(ctx context.Context, in *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	return &pb.DecryptResponse{Plaintext: "PlaintextData"}, nil
}

func main() {
	// load the SMTP configuration from the .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Failed to load the .env file: ", err)
	}

	// Create a new schemaManagementServiceDB
	cryptographyServiceDB, err := database.NewCryptographyServiceDB()
	if err != nil {
		log.Fatalf("failed to create a new SchemaManagementServiceDB: %v", err)
	}
	// ping the database
	err = cryptographyServiceDB.Db.Ping()
	if err != nil {
		log.Fatalf("failed to ping the database: %v", err)
	}

	// create a listener on TCP port 8080
	ls, err := net.Listen("tcp", ":8094")
	if err != nil {
		log.Fatal("Failed to listen: ", err)
	}

	// Close the listener when the application exits
	defer ls.Close()

	fmt.Println("Server started on port 8094")

	s := grpc.NewServer()
	pb.RegisterCryptographyManagerServer(s, &CryptographyServiceManager{cryptographyServiceDB: cryptographyServiceDB})

	if err := s.Serve(ls); err != nil {
		log.Fatal("Failed to serve the gRPC server: ", err)
	}
}

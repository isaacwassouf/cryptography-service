package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/isaacwassouf/cryptography-service/database"
	pb "github.com/isaacwassouf/cryptography-service/protobufs/cryptography_service"
	"github.com/isaacwassouf/cryptography-service/utils"
)

type CryptographyServiceManager struct {
	pb.UnimplementedCryptographyManagerServer
	cryptographyServiceDB *database.CryptographyServiceDB
}

func (s *CryptographyServiceManager) Encrypt(ctx context.Context, in *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	adminHashedPassword, err := utils.GetAdminHashedPassword(s.cryptographyServiceDB.Db)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get the admin hashed password")
	}

	// Derive the key and salt from the adminHashedPassword
	key, salt := utils.DeriveKey(adminHashedPassword, nil)

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate IV")
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create AES cipher")
	}

	paddedData, err := utils.PKCS7Padding([]byte(in.Plaintext), aes.BlockSize)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(aesCipher, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	encryptedData := hex.EncodeToString(salt) + "-" + hex.EncodeToString(iv) + "-" + hex.EncodeToString(ciphertext)

	return &pb.EncryptResponse{Ciphertext: encryptedData}, nil
}

func (s *CryptographyServiceManager) Decrypt(ctx context.Context, in *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	partitions := strings.Split(in.Ciphertext, "-")
	if len(partitions) != 3 {
		return nil, status.Error(codes.InvalidArgument, "invalid ciphertext")
	}

	salt, err := hex.DecodeString(partitions[0])
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid ciphertext")
	}

	iv, err := hex.DecodeString(partitions[1])
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid ciphertext")
	}

	ciphertext, err := hex.DecodeString(partitions[2])
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid ciphertext")
	}

	adminHashedPassword, err := utils.GetAdminHashedPassword(s.cryptographyServiceDB.Db)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get the admin hashed password")
	}

	// Derive the key and salt from the GetAdminHashedPassword
	key, _ := utils.DeriveKey(adminHashedPassword, salt)

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create AES cipher")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(aesCipher, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = utils.PKCS7UnPadding(plaintext)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to unpad plaintext")
	}

	return &pb.DecryptResponse{Plaintext: string(plaintext)}, nil
}

func main() {
	environment := utils.GetGoEnv()

	if environment == "development" {

		// load the SMTP configuration from the .env file
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Failed to load the .env file: ", err)
		}
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

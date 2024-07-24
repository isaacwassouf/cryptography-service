package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"

	"golang.org/x/crypto/pbkdf2"

	"github.com/isaacwassouf/cryptography-service/consts"
)

func GetAdminHashedPassword(db *sql.DB) (string, error) {
	var hashedPassword string
	err := db.QueryRow("SELECT password FROM admins order by created_at").Scan(&hashedPassword)
	if err != nil {
		return "", err
	}
	return hashedPassword, nil
}

func DeriveKey(password string, salt []byte) ([]byte, []byte) {
	if salt == nil {
		// Generate a random salt if one is not provided
		salt = make([]byte, 8)
		rand.Read(salt)
	}
	return pbkdf2.Key([]byte(password), salt, consts.ROUNDS, 32, sha256.New), salt
}

func GetGoEnv() string {
	environment, found := os.LookupEnv("GO_ENV")
	if !found {
		return "development"
	}

	return environment
}

func PKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 256 {
		return nil, errors.New("invalid block size")
	}

	if data == nil || len(data) == 0 {
		return nil, errors.New("invalid data")
	}

	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(data, padtext...), nil
}

func PKCS7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding size")
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("invalid padding size")
	}

	return data[:(length - unpadding)], nil
}

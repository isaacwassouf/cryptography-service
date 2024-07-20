package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"

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

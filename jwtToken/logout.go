package jwtToken

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt"
)

func LogoutCleanup(w http.ResponseWriter, r *http.Request) {
	tokenString, err := checkAccessCookie(r)
	if err == nil {
		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method : %v", token.Header["alg"])
			}
			return []byte(os.Getenv("ACCESS_SECRET")), nil
		})

		accessUuid := token.Claims.(jwt.MapClaims)["access_uuid"].(string)
		log.Println("logout - access-token UUID removed")
		delete(RefreshDetails, accessUuid)
	}

	tokenString, err = checkRefreshCookie(r)
	if err == nil {
		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method : %v", token.Header["alg"])
			}
			return []byte(os.Getenv("REFRESH_SECRET")), nil
		})

		refreshUuid := token.Claims.(jwt.MapClaims)["refresh_uuid"].(string)
		log.Println("logout - refresh-token UUID removed")
		delete(RefreshDetails, refreshUuid)
	}
	DeleteCookie(w)
	log.Println("logout - cookies removed")
	return
}

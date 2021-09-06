package jwtToken

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

type acTokenDetail struct {
	AccessUuid string
	Username   string
	Expired    bool
}

type rtTokenDetail struct {
	RefreshUuid string
	Username    string
	Expired     bool
}

//VerifyAccessTokenDetail validate Access-Token
func VerifyAccessTokenDetail(r *http.Request) (*acTokenDetail, error) {
	ac := &acTokenDetail{}
	tokenString, err := checkAccessCookie(r)
	if err != nil {
		return ac, err
	}

	accessUuid := ""

	token, err := verifyAccessTokenString(r, tokenString)
	if err != nil {
		log.Println(err)
		accessUuid, ok := token.Claims.(jwt.MapClaims)["access_uuid"].(string)
		log.Println("access-token UUID removed")
		if ok {
			delete(AccessDetails, accessUuid)
		}

		valid := token.Claims.(jwt.MapClaims).VerifyExpiresAt(time.Now().Unix(), false)
		if !valid {
			return &acTokenDetail{"", "", true}, err
		}
		return ac, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return ac, err
	}

	accessUuid, ok = claims["access_uuid"].(string)
	if !ok {
		return ac, fmt.Errorf("missing access_uuid")
	}

	username, ok := claims["username"].(string)
	if !ok {
		return ac, fmt.Errorf("missing username")
	}

	err = verifyAccessTokenID(accessUuid, username)
	if err != nil {
		return ac, fmt.Errorf("missing accessTokenID")
	}

	return &acTokenDetail{accessUuid, username, false}, nil
}

func verifyAccessTokenString(r *http.Request, tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method : %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return token, err
	}
	return token, nil
}

func verifyAccessTokenID(uuid, username string) error {
	user, ok := AccessDetails[uuid]
	if !ok || username != user {
		return fmt.Errorf("username mismatch")
	}
	return nil
}

//VerifyRefreshTokenDetail validate Refresh-Token
func VerifyRefreshTokenDetail(r *http.Request) (*rtTokenDetail, error) {
	rt := &rtTokenDetail{}
	tokenString, err := checkRefreshCookie(r)
	if err != nil {
		return rt, err
	}

	refreshUuid := ""

	token, err := verifyRefreshTokenString(r, tokenString)
	if err != nil {
		log.Println(err)
		refreshUuid, ok := token.Claims.(jwt.MapClaims)["refresh_uuid"].(string)
		log.Println("refresh-token UUID removed")
		if ok {
			delete(RefreshDetails, refreshUuid)
		}
		valid := token.Claims.(jwt.MapClaims).VerifyExpiresAt(time.Now().Unix(), false)
		if !valid {
			return &rtTokenDetail{"", "", true}, err
		}
		return rt, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return rt, err
	}

	refreshUuid, ok = claims["refresh_uuid"].(string)
	if !ok {
		return rt, fmt.Errorf("missing refresh_uuid")
	}

	username, ok := claims["username"].(string)
	if !ok {
		return rt, fmt.Errorf("missing username")
	}

	err = verifyRefreshTokenID(refreshUuid, username)
	if err != nil {
		return rt, fmt.Errorf("missing accessTokenID")
	}

	return &rtTokenDetail{refreshUuid, username, false}, nil
}

func verifyRefreshTokenString(r *http.Request, tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method : %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
	if err != nil {
		return token, err
	}
	return token, nil
}

func verifyRefreshTokenID(uuid, username string) error {
	user, ok := RefreshDetails[uuid]
	if !ok || username != user {
		return fmt.Errorf("username mismatch")
	}
	return nil
}

func checkAccessCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(acCookie)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func checkRefreshCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(rtCookie)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

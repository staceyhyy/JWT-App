package jwtToken

import (
	"net/http"
	"time"
)

const (
	acCookie = `aToken`
	rtCookie = `rToken`
)

// func SetCookie(w http.ResponseWriter, ac *Cookies, rt *Cookies) {
func SetCookie(w http.ResponseWriter, acTokenString, rtTokenString string) {
	http.SetCookie(w, &http.Cookie{
		Name:     acCookie,
		Value:    acTokenString,
		Expires:  time.Now().Add(time.Hour * 24 * 7),
		HttpOnly: true,
		Path:     "/",
		Domain:   "localhost",
		Secure:   true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     rtCookie,
		Value:    rtTokenString,
		Expires:  time.Now().Add(time.Hour * 24 * 7),
		HttpOnly: true,
		Path:     "/",
		Domain:   "localhost",
		Secure:   true,
	})
}

func DeleteCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     acCookie,
		HttpOnly: true,
		Path:     "/",
		Domain:   "localhost",
		Secure:   true,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     rtCookie,
		HttpOnly: true,
		Path:     "/",
		Domain:   "localhost",
		Secure:   true,
		MaxAge:   -1,
	})
}

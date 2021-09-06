package handler

import (
	"app/jwtToken"
	"log"
	"net/http"
)

func Logout(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL.Path, " - ", r.Method)

	jwtToken.LogoutCleanup(w, r)

	http.Redirect(w, r, "/token", http.StatusSeeOther)
	return
}

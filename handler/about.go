package handler

import (
	"app/jwtToken"
	"fmt"
	"log"
	"net/http"
)

func About(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL.Path, " - ", r.Method)

	acTokenDetail, err := jwtToken.VerifyAccessTokenDetail(r)
	if acTokenDetail.Expired {
		//refresh access token
		log.Println("about - access-token expired")
		log.Println("about - redirect to /refreshToken")
		http.Redirect(w, r, "/refreshToken?from=/about", http.StatusTemporaryRedirect)
		return
	}

	//token not valid
	if err != nil {
		log.Println("about - VerifyAccessTokenDetail - failed", err)
		jwtToken.DeleteCookie(w)
		log.Println("about - cookies removed")
		http.Error(w, "Unauthorized Access", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.Println("about - access-token is valid")
	fmt.Fprintln(w, "Hello World")
	w.WriteHeader(http.StatusOK)
	return
}

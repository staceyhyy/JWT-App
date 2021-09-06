package handler

import (
	"app/jwtToken"

	"log"
	"net/http"
)

func Refresh(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL.Path, " - ", r.Method)

	urlParm := r.URL.Query()

	rtTokenDetail, err := jwtToken.VerifyRefreshTokenDetail(r)
	if rtTokenDetail.Expired == true {
		jwtToken.DeleteCookie(w)
		log.Println("refresh - refresh-token expired")
		log.Println("refresh - redirect to /token")
		http.Redirect(w, r, "/token", http.StatusTemporaryRedirect)
		return
	}

	if err != nil {
		log.Println("refresh - VerifyRefreshTokenDetail - failed")
		http.Error(w, "Unauthorized Access", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.Println("refresh-token is valid")
	tokenString, err := jwtToken.CreateTokens(rtTokenDetail.Username)
	if err != nil {
		log.Println("refresh - create tokens failed")
		http.Error(w, "Unable to process", http.StatusUnprocessableEntity)
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	
	log.Println("refresh - new access-token & refresh-token created")
	err = jwtToken.SaveTokenID(rtTokenDetail.Username, tokenString)
	if err != nil {
		log.Println("refresh - saveTokenID failed")
		http.Error(w, "Unable to process", http.StatusUnprocessableEntity)
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	log.Println("refresh - delete cookies")
	jwtToken.DeleteCookie(w)
	jwtToken.SetCookie(w, tokenString.AccessToken, tokenString.RefreshToken)
	log.Println("refresh - new cookies set")

	tokenObject := Tokens{Jwt: TokenPair{tokenString.AccessToken, tokenString.RefreshToken}}
	log.Println("refresh - new access-token: ", tokenObject.Jwt.AccessToken)
	log.Println("refresh - new refresh-token: ", tokenObject.Jwt.RefreshToken)

	log.Println("refresh - back to the calling page - ", urlParm["from"][0])
	http.Redirect(w, r, urlParm["from"][0], http.StatusSeeOther)
	return
}

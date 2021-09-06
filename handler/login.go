package handler

import (
	"app/jwtToken"
	"html/template"

	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenPair struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type Tokens struct {
	Jwt TokenPair `json:"token"`
}

var users = map[string]string{
	"user": "$2a$10$BLrUjUoU9/vKdqmak8I4I.K4w91RLvMVugfGGB3arATVn420t3FLG",
}

var tpl *template.Template

func Login(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL.Path, " - ", r.Method)

	tpl = template.Must(template.ParseGlob("template/*.html"))

	if r.Method == "GET" {
		err := tpl.ExecuteTemplate(w, "index.html", nil)
		if err != nil {
			log.Fatalln(err)
			return
		}
		return
	}

	if r.Method == "POST" {
		var credential Credentials

		credential.Username = r.FormValue("username")
		credential.Password = r.FormValue("password")

		if credential.Username == "" || credential.Password == "" {
			http.Error(w, "Invalid username/password", http.StatusUnauthorized)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		password := users[credential.Username]
		err := bcrypt.CompareHashAndPassword([]byte(password), []byte(credential.Password))
		if err != nil {
			http.Error(w, "Invalid username/password", http.StatusUnauthorized)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenString, err := jwtToken.CreateTokens(credential.Username)
		if err != nil {
			http.Error(w, "Unable to process", http.StatusUnprocessableEntity)
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}

		err = jwtToken.SaveTokenID(credential.Username, tokenString)
		if err != nil {
			http.Error(w, "Unable to process", http.StatusUnprocessableEntity)
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}

		jwtToken.SetCookie(w, tokenString.AccessToken, tokenString.RefreshToken)

		//return token as json object
		tokenObject := Tokens{Jwt: TokenPair{tokenString.AccessToken, tokenString.RefreshToken}}
		log.Println("new access-token: ", tokenObject.Jwt.AccessToken)
		log.Println("new refresh-token: ", tokenObject.Jwt.RefreshToken)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(tokenObject)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	return
}

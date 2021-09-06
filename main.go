package main

import (
	"app/handler"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.Handle("/favicon.ico", http.NotFoundHandler())
	r.HandleFunc("/token", handler.Login)
	r.HandleFunc("/about", handler.About).Methods("GET")
	r.HandleFunc("/refreshToken", handler.Refresh).Methods("GET")
	r.HandleFunc("/logout", handler.Logout)

	s := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	err := s.ListenAndServeTLS("./cert/cert.pem", "./cert/key.pem")
	if err != nil {
		log.Fatal("ListenAndServe : ", err)
	}
}

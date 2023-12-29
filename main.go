package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/rs/cors"
)

var (
	ActiveKeySet jwk.Set
)

func keyfunc(tok *jwt.Token) (interface{}, error) {
	kid, ok := tok.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("no key id")
	}
	key, keyfound := ActiveKeySet.LookupKeyID(kid)
	if !keyfound {
		return nil, fmt.Errorf("token key with id %s not found", kid)
	}
	var rawkey interface{}
	err := key.Raw(&rawkey)
	if err != nil {
		return nil, fmt.Errorf("token key with id %s key error %v", kid, err)
	}
	return rawkey, nil
}

func validate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		log.Printf("Bad Method")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	auth := r.Header.Get("Authorization")
	if len(auth) < 1 || !strings.HasPrefix(auth, "Bearer ") {
		log.Printf("No Auth")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tokenstring := auth[7:]
	token, err := jwt.Parse(tokenstring, keyfunc, jwt.WithIssuedAt(), jwt.WithExpirationRequired())
	if err != nil {
		log.Printf("Failed to parse the JWT. %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !token.Valid {
		log.Printf("Token is not valid. %s", tokenstring)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	log.Printf("Validated Token\n")
	w.WriteHeader(http.StatusNoContent)
}

func setupcors() *cors.Cors {
	originsenv := os.Getenv("CORS_ORIGINS")
	if len(originsenv) > 0 {
		origins := strings.Split(originsenv, "'")
		options := cors.Options{
			AllowedOrigins:   origins,
			AllowedMethods:   []string{http.MethodGet},
			AllowCredentials: true,
			AllowedHeaders:   []string{"authorization"},
		}
		return cors.New(options)
	} else {
		return cors.Default()
	}
}

func setupKeyset() {
	keysetenv := os.Getenv("JWTKS")
	var err error
	ActiveKeySet, err = jwk.Parse([]byte(keysetenv))
	if err != nil {
		log.Printf("Error parsing keyset %v\n", err)
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/Validate", validate)

	setupKeyset()
	corsobj := setupcors()
	handler := corsobj.Handler(mux)
	http.ListenAndServe("0.0.0.0:8080", handler)
}

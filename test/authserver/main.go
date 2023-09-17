package main

import (
	"errors"
	"net/http"
	"time"

	oauth "github.com/autumnsaury/gin-oauth"
	cors "github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

/*
	   Authorization Server Example

	    Generate Token using username & password

	    	POST http://localhost:3000/token
			User-Agent: Fiddler
			Host: localhost:3000
			Content-Length: 50
			Content-Type: application/x-www-form-urlencoded

			grant_type=password&username=user01&password=12345

		Generate Token using clientId & secret

	    	POST http://localhost:3000/auth
			User-Agent: Fiddler
			Host: localhost:3000
			Content-Length: 66
			Content-Type: application/x-www-form-urlencoded

			grant_type=client_credentials&client_id=abcdef&client_secret=12345

		Refresh Token

			POST http://localhost:3000/token
			User-Agent: Fiddler
			Host: localhost:3000
			Content-Length: 50
			Content-Type: application/x-www-form-urlencoded

			grant_type=refresh_token&refresh_token={the refresh_token obtained in the previous response}
*/
func main() {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())
	router.Use(cors.Default()) // enable Cross-Origin Resource Sharing
	gin.SetMode(gin.DebugMode)
	registerAPI(router)
	router.Run(":3000")
}

func registerAPI(router *gin.Engine) {
	s := oauth.NewOAuthBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		time.Hour*24*14,
		&TestUserVerifier{},
		nil)
	router.POST("/token", s.UserCredentials)
	router.POST("/auth", s.ClientCredentials)
}

// TestUserVerifier provides user credentials verifier for testing.
type TestUserVerifier struct{}

// ValidateUser validates username and password returning an error if the user credentials are wrong
func (*TestUserVerifier) ValidateUser(username, password string, scope []string, req *http.Request) error {
	if username == "user01" && password == "12345" {
		return nil
	}
	return errors.New("wrong user")
}

// ValidateClient validates clientId and secret returning an error if the client credentials are wrong
func (*TestUserVerifier) ValidateClient(clientID, clientSecret string, scope []string, req *http.Request) error {
	if clientID == "abcdef" && clientSecret == "12345" {
		return nil
	}
	return errors.New("wrong client")
}

// AddClaims provides additional claims to the token
func (*TestUserVerifier) AddClaims(credential, tokenID, tokenType string, scope []string) (map[string]string, error) {
	claims := make(map[string]string)
	claims["customerId"] = "1001"
	claims["customerData"] = `{"OrderDate":"2016-12-14","OrderId":"9999"}`
	return claims, nil
}

// StoreTokenId saves the token Id generated for the user
func (*TestUserVerifier) StoreTokenId(credential, tokenId, tokenType string) error {
	return nil
}

// AddProperties provides additional information to the token response
func (*TestUserVerifier) AddProperties(credential, tokenId, tokenType string, scope []string) (map[string]string, error) {
	props := make(map[string]string)
	props["customerName"] = "Gopher"
	return props, nil
}

// ValidateTokenId validates token Id
func (*TestUserVerifier) ValidateTokenId(credential, tokenId, tokenType string) error {
	return nil
}

// ValidateCode validates token Id
func (*TestUserVerifier) ValidateCode(clientID, clientSecret, code, redirectURI string, req *http.Request) (string, error) {
	return "", nil
}

func (*TestUserVerifier) RevokeToken(id string) error {
	return nil
}

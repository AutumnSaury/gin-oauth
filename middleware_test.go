package oauth

import (
	"errors"
	"slices"
	"testing"

	jwt "github.com/golang-jwt/jwt/v4"
)

var _mut *BearerAuthentication

func init() {
	_mut = NewBearerAuthentication(
		"mySecretKey-10101",
		jwt.SigningMethodHS256,
		&TokenValidator{},
	)
}

func TestAuthorizationHeader(t *testing.T) {
	code, resp := _sut.generateTokenResponse("password", "user111", "password111", "", "", "", "", nil)
	if code != 200 {
		t.Fatalf("Error StatusCode = %d", code)
	}
	t.Logf("Token response: %v", resp)

	header := "Bearer " + resp.(*TokenResponse).Token
	token, err := _mut.checkAuthorizationHeader(header)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Verified token : %v", token)
}

func TestExpiredAuthorizationHeader(t *testing.T) {
	header := `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ1c2VyMDEiLCJleHAiOjE2MDAwMDAxMjAsImp0aSI6IjhmOTQ2ZWU1LWI2YWYtNGFiZS1hOGY3LTljZjk2ZTUzZjFhZSIsImlhdCI6MTYwMDAwMDAwMCwibmJmIjoxNjAwMDAwMDAwLCJ0eXBlIjoiVSIsImZvcl9yZWZyZXNoIjpmYWxzZSwic2NvcGUiOltdLCJjbGFpbXMiOnsiY3VzdG9tZXJEYXRhIjoie1wiT3JkZXJEYXRlXCI6XCIyMDE2LTEyLTE0XCIsXCJPcmRlcklkXCI6XCI5OTk5XCJ9IiwiY3VzdG9tZXJJZCI6IjEwMDEifX0.AlhstC2aUlzUbWlJ-pD-bQflMxxjKGeM1QzOk4fSw40`
	_, err := _mut.checkAuthorizationHeader(header)
	if err == nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Error : %v", err)
}

type TokenValidator struct {
	requiredScopes []string
}

func (tv TokenValidator) ValidateAccessToken(t *Token) error {
	for _, s := range tv.requiredScopes {
		if !slices.Contains(t.Scope, s) {
			return errors.New("permission denied")
		}
	}
	return nil
}

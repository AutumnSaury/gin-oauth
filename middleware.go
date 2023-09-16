package oauth

import (
	"strings"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v4"
)

// BearerAuthentication middleware for Gin-Gonic
type BearerAuthentication struct {
	secretKey       string
	signingMethod   jwt.SigningMethod
	customValidator AccessTokenValidator
}

type AccessTokenValidator interface {
	ValidateAccessToken(token *Token, ctx *gin.Context) error
}

// NewBearerAuthentication create a BearerAuthentication middleware
func NewBearerAuthentication(secretKey string, signingMethod jwt.SigningMethod, customValidator AccessTokenValidator) *BearerAuthentication {
	ba := &BearerAuthentication{secretKey: secretKey}
	if signingMethod == nil {
		signingMethod = jwt.SigningMethodHS256
	}
	ba.signingMethod = signingMethod
	ba.customValidator = customValidator

	return ba
}

// Authorize is the OAuth 2.0 middleware for Gin-Gonic resource server.
// Authorize creates a BearerAuthentication middlever and return the Authorize method.
func Authorize(secretKey string, signingMethod jwt.SigningMethod, customValidator AccessTokenValidator) gin.HandlerFunc {
	return NewBearerAuthentication(secretKey, signingMethod, customValidator).Authorize
}

// Authorize verifies the bearer token authorizing or not the request.
// Token is retreived from the Authorization HTTP header that respects the format
// Authorization: Bearer {access_token}
func (ba *BearerAuthentication) Authorize(ctx *gin.Context) {
	auth := ctx.Request.Header.Get("Authorization")
	token, err := ba.checkAuthorizationHeader(auth)

	if err != nil {
		ctx.Error(err)
		ctx.Abort()
	} else if err := ba.customValidator.ValidateAccessToken(token, ctx); err != nil {
		ctx.Error(err)
		ctx.Abort()
	} else {
		ctx.Set("oauth.audience", token.Audience)
		ctx.Set("oauth.claims", token.Claims)
		ctx.Set("oauth.scope", token.Scope)
		ctx.Set("oauth.tokentype", token.TokenType)
		ctx.Set("oauth.accesstoken", auth[7:])
		ctx.Next()
	}
}

func (ba *BearerAuthentication) validateAccessToken(token string) (*Token, error) {
	t, err := jwt.ParseWithClaims(token, &Token{},
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != ba.signingMethod {
				return nil, ErrInvalidAccessTokenSigningMethod
			}

			if c, ok := token.Claims.(*Token); !ok && !token.Valid {
				return nil, ErrTokenInvalid
			} else if c.ForRefresh {
				return nil, ErrNotAccessToken
			}

			return []byte(ba.secretKey), nil
		},
	)

	return t.Claims.(*Token), err
}

// Check header and token.
func (ba *BearerAuthentication) checkAuthorizationHeader(auth string) (t *Token, err error) {
	if len(auth) < 7 {
		return nil, ErrInvalidAuthenticationScheme
	}
	authType := strings.ToLower(auth[:6])
	if authType != "bearer" {
		return nil, ErrInvalidAuthenticationScheme
	}
	token, err := ba.validateAccessToken(auth[7:])
	if err != nil {
		return nil, err
	}

	return token, nil
}

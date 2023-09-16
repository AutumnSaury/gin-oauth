package oauth

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	uuid "github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v4"
)

const (
	TOKEN_TYPE = "Bearer"
)

// CredentialsVerifier defines the interface of the user and client credentials verifier.
type CredentialsVerifier interface {
	// Validate username and password returning an error if the user credentials are wrong
	ValidateUser(username, password string, scope []string, req *http.Request) error
	// Validate clientId and secret returning an error if the client credentials are wrong
	ValidateClient(clientID, clientSecret string, scope []string, req *http.Request) error
	// Provide additional claims to the token
	AddClaims(credential, tokenID, tokenType string, scope []string) (map[string]string, error)
	// Optionally store the tokenID generated for the user
	StoreTokenId(credential, tokenID, tokenType string) error
	// Provide additional information to the authorization server response
	AddProperties(credential, tokenID, tokenType string, scope []string) (map[string]string, error)
	// Optionally validate previously stored tokenID during refresh request
	ValidateTokenId(credential, tokenID, tokenType string) error
}

// AuthorizationCodeVerifier defines the interface of the Authorization Code verifier
type AuthorizationCodeVerifier interface {
	// ValidateCode checks the authorization code and returns the user credential
	ValidateCode(clientID, clientSecret, code, redirectURI string, req *http.Request) (string, error)
}

// OAuthBearerServer is the OAuth 2 Bearer Server implementation.
type OAuthBearerServer struct {
	secretKey     string
	TokenTTL      time.Duration
	RefreshTTL    time.Duration
	verifier      CredentialsVerifier
	signingMethod jwt.SigningMethod
}

// NewOAuthBearerServer creates new OAuth 2 Bearer Server
func NewOAuthBearerServer(
	secretKey string,
	ttl time.Duration,
	refreshTtl time.Duration,
	verifier CredentialsVerifier,
	signingMethod jwt.SigningMethod,
) *OAuthBearerServer {

	if signingMethod == nil {
		signingMethod = jwt.SigningMethodHS256
	}

	obs := &OAuthBearerServer{
		secretKey:     secretKey,
		TokenTTL:      ttl,
		RefreshTTL:    refreshTtl,
		verifier:      verifier,
		signingMethod: signingMethod,
	}
	return obs
}

// UserCredentials manages password grant type requests
func (s *OAuthBearerServer) UserCredentials(ctx *gin.Context) {
	grantType := ctx.PostForm("grant_type")
	// grant_type password variables
	username := ctx.PostForm("username")
	password := ctx.PostForm("password")
	scope := ctx.PostForm("scope")
	if username == "" || password == "" {
		ctx.Error(ErrInvalidGrant)
		return
	}
	// grant_type refresh_token
	refreshToken := ctx.PostForm("refresh_token")
	resp, err := s.generateTokenResponse(grantType, username, password, refreshToken, scope, "", "", ctx.Request)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, resp)
}

// ClientCredentials manages client credentials grant type requests
func (s *OAuthBearerServer) ClientCredentials(ctx *gin.Context) {
	grantType := ctx.PostForm("grant_type")
	// grant_type client_credentials variables
	clientId := ctx.PostForm("client_id")
	clientSecret := ctx.PostForm("client_secret")
	if clientId == "" || clientSecret == "" {
		ctx.Error(ErrInvalidGrant)
		return
	}
	scope := ctx.PostForm("scope")
	// grant_type refresh_token
	refreshToken := ctx.PostForm("refresh_token")
	resp, err := s.generateTokenResponse(grantType, clientId, clientSecret, refreshToken, scope, "", "", ctx.Request)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, resp)
}

// AuthorizationCode manages authorization code grant type requests for the phase two of the authorization process
func (s *OAuthBearerServer) AuthorizationCode(ctx *gin.Context) {
	grantType := ctx.PostForm("grant_type")
	// grant_type client_credentials variables
	clientId := ctx.PostForm("client_id")
	clientSecret := ctx.PostForm("client_secret") // not mandatory
	code := ctx.PostForm("code")
	redirectURI := ctx.PostForm("redirect_uri") // not mandatory
	scope := ctx.PostForm("scope")              // not mandatory
	if clientId == "" {
		ctx.Error(ErrInvalidClient)
		return
	}
	resp, err := s.generateTokenResponse(grantType, clientId, clientSecret, "", scope, code, redirectURI, ctx.Request)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, resp)
}

// Generate token response
func (s *OAuthBearerServer) generateTokenResponse(grantType, credential, secret, refreshToken, unsplitScope, code, redirectURI string, req *http.Request) (*TokenResponse, error) {
	var scope []string

	if unsplitScope == "" {
		scope = make([]string, 0)
	} else {
		scope = strings.Split(unsplitScope, " ")
	}

	// check grant_Type
	if grantType == "password" {
		err := s.verifier.ValidateUser(credential, secret, scope, req)
		if err == nil {
			token, refresh, err := s.generateTokens(credential, "U", scope)
			if err == nil {
				// Store token id
				err = s.verifier.StoreTokenId(credential, token.Id, token.TokenType)
				if err != nil {
					return nil, err
				}
				resp, err := s.cryptTokens(token, refresh)
				if err == nil {
					return resp, nil
				} else {
					return nil, err
				}
			} else {
				return nil, err
			}

		} else {
			//not autorized
			return nil, err
		}
	} else if grantType == "client_credentials" {
		err := s.verifier.ValidateClient(credential, secret, scope, req)
		if err == nil {
			token, refresh, err := s.generateTokens(credential, "C", scope)
			if err == nil {
				// Store token id
				err = s.verifier.StoreTokenId(credential, token.Id, token.TokenType)
				if err != nil {
					return nil, err
				}
				resp, err := s.cryptTokens(token, refresh)
				if err == nil {
					return resp, nil
				} else {
					return nil, err
				}
			} else {
				return nil, err
			}
		} else {
			//not autorized
			return nil, err
		}
	} else if grantType == "authorization_code" {
		if codeVerifier, ok := s.verifier.(AuthorizationCodeVerifier); ok {
			user, err := codeVerifier.ValidateCode(credential, secret, code, redirectURI, req)
			if err == nil {
				token, refresh, err := s.generateTokens(user, "A", scope)
				if err == nil {
					// Store token id
					err = s.verifier.StoreTokenId(user, token.Id, token.TokenType)
					if err != nil {
						return nil, err
					}
					resp, err := s.cryptTokens(token, refresh)
					if err == nil {
						return resp, nil
					} else {
						return nil, err
					}
				} else {
					return nil, err
				}
			} else {
				//not autorized
				return nil, err
			}
		} else {
			//not autorized
			return nil, ErrUnsupportedGrantType
		}
	} else if grantType == "refresh_token" {
		// refresh token
		refresh, err := s.validateRefreshToken(refreshToken)

		if err == nil {
			err = s.verifier.ValidateTokenId(refresh.Audience, refresh.Id, refresh.TokenType)
			if err == nil {
				// generate new token
				token, refresh, err := s.generateTokens(refresh.Audience, refresh.TokenType, refresh.Scope)
				if err == nil {
					// Store token id
					err = s.verifier.StoreTokenId(refresh.Audience, token.Id, token.TokenType)
					if err != nil {
						return nil, err
					}
					resp, err := s.cryptTokens(token, refresh)
					if err == nil {
						return resp, nil
					} else {
						return nil, err
					}
				} else {
					return nil, err
				}
			} else {
				//not autorized invalid token Id
				return nil, err
			}
		} else {
			//not autorized
			return nil, err
		}
	} else {
		// Invalid request
		return nil, ErrInvalidGrant
	}
}

func (s *OAuthBearerServer) generateTokens(username string, tokenType string, scope []string) (token *Token, refresh *Token, err error) {
	token = &Token{
		Audience:   username,
		ExpiresAt:  time.Now().UTC().Unix() + int64(s.TokenTTL.Seconds()),
		IssuedAt:   time.Now().UTC().Unix(),
		NotBefore:  time.Now().UTC().Unix(),
		TokenType:  tokenType,
		ForRefresh: false,
		Scope:      scope,
	}
	// generate token Id
	token.Id = uuid.Must(uuid.NewV4()).String()
	if s.verifier != nil {
		claims, err := s.verifier.AddClaims(username, token.Id, token.TokenType, token.Scope)
		if err == nil {
			token.Claims = claims
		} else {
			// claims error
			return nil, nil, err
		}
	}
	// create refresh token
	refresh = &Token{
		Id:         token.Id,
		Audience:   username,
		ExpiresAt:  time.Now().UTC().Unix() + int64(s.RefreshTTL.Seconds()),
		IssuedAt:   time.Now().UTC().Unix(),
		NotBefore:  time.Now().UTC().Unix(),
		TokenType:  tokenType,
		ForRefresh: true,
		Scope:      scope,
	}

	return token, refresh, nil
}

func (s *OAuthBearerServer) cryptTokens(token *Token, refresh *Token) (resp *TokenResponse, err error) {
	ctoken, err := jwt.NewWithClaims(s.signingMethod, token).SignedString([]byte(s.secretKey))
	if err != nil {
		return nil, err
	}
	crefresh, err := jwt.NewWithClaims(s.signingMethod, refresh).SignedString([]byte(s.secretKey))
	if err != nil {
		return nil, err
	}
	resp = &TokenResponse{Token: ctoken, RefreshToken: crefresh, TokenType: TOKEN_TYPE, ExpiresIn: (int64)(s.TokenTTL / time.Second)}

	if s.verifier != nil {
		// add properties
		props, err := s.verifier.AddProperties(token.Audience, token.Id, token.TokenType, token.Scope)
		if err == nil {
			resp.Properties = props
		}
	}
	return resp, nil
}

func (s *OAuthBearerServer) validateRefreshToken(token string) (*Token, error) {
	t, err := jwt.ParseWithClaims(token, &Token{},
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != s.signingMethod {
				return nil, ErrInvalidRefreshTokenSigningMethod
			}

			if c, ok := token.Claims.(*Token); !ok && !token.Valid {
				return nil, ErrTokenInvalid
			} else if !c.ForRefresh {
				return nil, ErrNotRefreshToken
			}

			return []byte(s.secretKey), nil
		},
	)

	if err != nil {
		return nil, err
	}

	return t.Claims.(*Token), nil
}

package oauth

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	uuid "github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v4"
)

const (
	TokenType = "Bearer"
)

var (
	AvailableGrantTypes               = []string{"password", "client_credentials", "authorization_code", "refresh_token"}
	PasswordWithRefreshToken          = []string{"password", "refresh_token"}
	ClientCredentialsWithRefreshToken = []string{"client_credentials", "refresh_token"}
	AuthorizationCodeOnly             = []string{"authorization_code"}
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
	// Optionally revoke a token by it's ID
	RevokeToken(tokenID string) error
}

// AuthorizationCodeVerifier defines the interface of the Authorization Code verifier
type AuthorizationCodeVerifier interface {
	// ValidateCode checks the authorization code and returns the user credential
	ValidateCode(clientID, clientSecret, code, redirectURI string, req *http.Request) (string, error)
}

// OAuthBearerServer is the OAuth 2 Bearer Server implementation.
type OAuthBearerServer struct {
	secretKey     string
	tokenTTL      time.Duration
	refreshTTL    time.Duration
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
		tokenTTL:      ttl,
		refreshTTL:    refreshTtl,
		verifier:      verifier,
		signingMethod: signingMethod,
	}
	return obs
}

// GetOAuthServer returns the OAuth 2.0 server handler
func (s *OAuthBearerServer) GetOAuthServer(allowedGrantTypes []string) gin.HandlerFunc {

	if len(allowedGrantTypes) != 0 {
		for _, gt := range allowedGrantTypes {
			if !slices.Contains(AvailableGrantTypes, gt) {
				panic("Invalid grant type: " + gt)
			}
		}
	} else {
		panic("No grant type provided")
	}

	return func(ctx *gin.Context) {
		grantType := ctx.PostForm("grant_type")

		if !slices.Contains(allowedGrantTypes, grantType) {
			ctx.Error(ErrUnsupportedGrantType)
			return
		}

		switch grantType {
		case "password":
			username := ctx.PostForm("username")
			password := ctx.PostForm("password")
			scope := ctx.PostForm("scope")
			if username == "" || password == "" {
				ctx.Error(ErrInvalidGrant)
				return
			}
			resp, err := s.generateTokenResponseForPasswordGrant(username, password, scope, ctx.Request)
			if err != nil {
				ctx.Error(err)
				return
			}
			ctx.JSON(http.StatusOK, resp)

		case "client_credentials":
			clientId := ctx.PostForm("client_id")
			clientSecret := ctx.PostForm("client_secret")
			if clientId == "" || clientSecret == "" {
				ctx.Error(ErrInvalidGrant)
				return
			}
			scope := ctx.PostForm("scope")
			resp, err := s.generateTokenResponseForClientCredentialsGrant(clientId, clientSecret, scope, ctx.Request)
			if err != nil {
				ctx.Error(err)
				return
			}
			ctx.JSON(http.StatusOK, resp)
		case "authorization_code":
			clientId := ctx.PostForm("client_id")
			clientSecret := ctx.PostForm("client_secret") // not mandatory
			code := ctx.PostForm("code")
			redirectURI := ctx.PostForm("redirect_uri") // not mandatory
			scope := ctx.PostForm("scope")              // not mandatory
			if clientId == "" {
				ctx.Error(ErrInvalidClient)
				return
			}
			resp, err := s.generateTokenResponseForAuthorizationCodeGrant(clientId, clientSecret, scope, code, redirectURI, ctx.Request)
			if err != nil {
				ctx.Error(err)
				return
			}
			ctx.JSON(http.StatusOK, resp)
		case "refresh_token":
			refreshToken := ctx.PostForm("refresh_token")
			resp, err := s.generateTokenResponseForRefreshGrant(refreshToken)
			if err != nil {
				ctx.Error(err)
				return
			}
			ctx.JSON(http.StatusOK, resp)
		default:
			ctx.Error(ErrUnsupportedGrantType)
			return
		}
	}
}

// TokenRevocationServer manages token revocation requests, it revokes a valid token, along with all tokens share the same id with it.
// We broke the standard to make a 4xx response when the client intend to revoke an invalid token.
func (s *OAuthBearerServer) TokenRevocationServer(ctx *gin.Context) {
	token := ctx.PostForm("token")
	if token == "" {
		ctx.Error(ErrInvalidRevocationRequest)
		return
	}

	hint := ctx.PostForm("token_type_hint")

	if hint != "" && hint != "access_token" && hint != "refresh_token" {
		ctx.Error(ErrUnsupportedTokenType)
		return
	} else if hint == "refresh_token" {
		tc, err := s.validateRefreshToken(token)
		if err != nil {
			ctx.Error(ErrInvalidRevocationRequest)
			return
		}

		err = s.verifier.RevokeToken(tc.Id)
		if err != nil {
			ctx.Error(err)
			return
		}
		ctx.Status(http.StatusOK)
	} else if hint == "access_token" {
		ba := NewBearerAuthentication(s.secretKey, s.signingMethod, nil)
		tc, err := ba.validateAccessToken(token)
		if err != nil {
			ctx.Error(ErrInvalidRevocationRequest)
			return
		}

		err = s.verifier.RevokeToken(tc.Id)
		if err != nil {
			ctx.Error(err)
			return
		}

		ctx.Status(http.StatusOK)
	} else {
		// try to revoke refresh token
		tc, err := s.validateRefreshToken(token)
		if err == nil {
			err = s.verifier.RevokeToken(tc.Id)
			if err != nil {
				ctx.Error(err)
				return
			}
			ctx.Status(http.StatusOK)
		} else if err == ErrNotRefreshToken {
			// try to revoke access token
			ba := NewBearerAuthentication(s.secretKey, s.signingMethod, nil)
			tc, err := ba.validateAccessToken(token)
			if err == nil {
				err = s.verifier.RevokeToken(tc.Id)
				if err != nil {
					ctx.Error(err)
					return
				}
				ctx.Status(http.StatusOK)
			} else if err == ErrNotAccessToken {
				ctx.Error(ErrUnsupportedTokenType)
				return
			} else {
				ctx.Error(err)
				return
			}
		} else {
			ctx.Error(err)
			return
		}
	}
}

// Generate token response for refresh token grant flow
func (s *OAuthBearerServer) generateTokenResponseForRefreshGrant(refreshToken string) (*TokenResponse, error) {
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
}

// Generate token response for password grant flow
func (s *OAuthBearerServer) generateTokenResponseForPasswordGrant(credential string, password string, scopeString string, req *http.Request) (*TokenResponse, error) {
	var scope []string

	if scopeString == "" {
		scope = make([]string, 0)
	} else {
		scope = strings.Split(scopeString, " ")
	}

	err := s.verifier.ValidateUser(credential, password, scope, req)
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
}

// Generate token response for client credentials grant flow
func (s *OAuthBearerServer) generateTokenResponseForClientCredentialsGrant(credential string, secret string, scopeString string, req *http.Request) (*TokenResponse, error) {
	var scope []string

	if scopeString == "" {
		scope = make([]string, 0)
	} else {
		scope = strings.Split(scopeString, " ")
	}

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
}

// Generate token response for authorization code grant flow
func (s *OAuthBearerServer) generateTokenResponseForAuthorizationCodeGrant(credential string, secret string, scopeString string, code string, redirectURI string, req *http.Request) (*TokenResponse, error) {
	var scope []string

	if scopeString == "" {
		scope = make([]string, 0)
	} else {
		scope = strings.Split(scopeString, " ")
	}

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
}

func (s *OAuthBearerServer) generateTokens(username string, tokenType string, scope []string) (token *Token, refresh *Token, err error) {
	token = &Token{
		Audience:   username,
		ExpiresAt:  time.Now().UTC().Unix() + int64(s.tokenTTL.Seconds()),
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
		ExpiresAt:  time.Now().UTC().Unix() + int64(s.refreshTTL.Seconds()),
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
	resp = &TokenResponse{
		Token:                 ctoken,
		RefreshToken:          crefresh,
		TokenType:             TokenType,
		ExpiresIn:             (int64)(s.tokenTTL / time.Second),
		RefreshTokenExpiresIn: (int64)(s.refreshTTL / time.Second),
		Scope:                 strings.Join(token.Scope, ""),
	}

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

package oauth

import (
	"net/http"
)

// OauthErrorResponse is the error response structure.
// When error occours in parts of this lib, it would be pushed into gin.Context.Errors.
// Handle them with a custom middleware.
type OauthErrorResponse struct {
	ErrorName        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorUrl         string `json:"error_url,omitempty"`
	Header           string `json:"-"` // WWW-Authenticate header, used to indicate available authentication scheme(s), in our case it's Bearer
	Status           int    `json:"-"` // HTTP status code
	NoCache          bool   `json:"-"` // Set Cache-Control: no-store
}

func (e OauthErrorResponse) Error() string {
	return e.ErrorName
}

var (
	// Errors for server

	ErrInvalidRefreshTokenSigningMethod = OauthErrorResponse{
		ErrorName:        "invalid_request",
		ErrorDescription: "token used an invalid signing method",
		Header:           "Bearer",
		Status:           http.StatusBadRequest,
		NoCache:          true,
	}

	ErrNotRefreshToken = OauthErrorResponse{
		ErrorName:        "invalid_request",
		ErrorDescription: "token provided was not a refresh token",
		Header:           "Bearer",
		Status:           http.StatusBadRequest,
		NoCache:          true,
	}

	ErrInvalidGrant = OauthErrorResponse{
		ErrorName:        "invalid_grant",
		ErrorDescription: "invalid password or client_secret",
		Header:           "Bearer",
		Status:           http.StatusBadRequest,
		NoCache:          true,
	}

	ErrInvalidAuthenticationScheme = OauthErrorResponse{
		ErrorName:        "invalid_request",
		ErrorDescription: "invalid authentication scheme, bearer wanted",
		Header:           "Bearer",
		Status:           http.StatusBadRequest,
		NoCache:          true,
	}

	ErrUnsupportedGrantType = OauthErrorResponse{
		ErrorName:        "unsupported_grant_type",
		ErrorDescription: "grant type required not available on this server",
		Header:           "Bearer",
		Status:           http.StatusBadRequest,
		NoCache:          true,
	}

	ErrInvalidScope = OauthErrorResponse{
		ErrorName:        "invalid_scope",
		ErrorDescription: "you requested for an invalid scope",
		Header:           "Bearer",
		Status:           http.StatusBadRequest,
		NoCache:          true,
	}

	ErrInvalidClient = OauthErrorResponse{
		ErrorName:        "invalid_client",
		ErrorDescription: "invalid client id or secret",
		Header:           "Bearer",
		Status:           http.StatusUnauthorized,
		NoCache:          true,
	}

	ErrTokenIdStorageFail = OauthErrorResponse{
		ErrorName:        "server_error",
		ErrorDescription: "failed to store token id",
		Header:           "Bearer",
		Status:           http.StatusInternalServerError,
		NoCache:          true,
	}

	// Errors for middleware

	ErrInvalidAccessTokenSigningMethod = OauthErrorResponse{
		ErrorName:        "invalid_token",
		ErrorDescription: "token used an invalid signing method",
		Header:           "Bearer",
		Status:           http.StatusUnauthorized,
	}

	ErrNotAccessToken = OauthErrorResponse{
		ErrorName:        "invalid_token",
		ErrorDescription: "token provided was not a access token",
		Header:           "Bearer",
		Status:           http.StatusUnauthorized,
	}

	ErrTokenInvalid = OauthErrorResponse{
		ErrorName:        "invalid_token",
		ErrorDescription: "the token is invalid",
		Header:           "Bearer",
		Status:           http.StatusUnauthorized,
	}

	ErrTokenUsedBeforeIssued = OauthErrorResponse{
		ErrorName:        "invalid_token",
		ErrorDescription: "the token is not yet issued",
		Header:           "Bearer",
		Status:           http.StatusUnauthorized,
	}

	ErrTokenUsedBeforeValid = OauthErrorResponse{
		ErrorName:        "invalid_token",
		ErrorDescription: "the token is not valid yet",
		Header:           "Bearer",
		Status:           http.StatusUnauthorized,
	}

	ErrTokenExpire = OauthErrorResponse{
		ErrorName:        "invalid_token",
		ErrorDescription: "the token has expired",
		Header:           "Bearer",
		Status:           http.StatusUnauthorized,
	}

	ErrInsufficientScope = OauthErrorResponse{
		ErrorName:        "insufficient_scope",
		ErrorDescription: "the request requires higher privileges than provided by the access token",
		Header:           "Bearer",
		Status:           http.StatusUnauthorized,
	}
)

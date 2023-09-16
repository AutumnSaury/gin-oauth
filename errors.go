package oauth

import "errors"

var (
	ErrInvalidSigningMethod        = errors.New("invalid signing method")
	ErrTokenInvalid                = errors.New("invalid token")
	ErrNotAccessToken              = errors.New("not access token")
	ErrNotRefreshToken             = errors.New("not refresh token")
	ErrInvalidAuthenticationScheme = errors.New("invalid authentication scheme, bearer wanted")
	ErrTokenUsedBeforeIssued       = errors.New("Token used before issued")
	ErrTokenUsedBeforeValid        = errors.New("Token is not valid yet")
	ErrTokenExpire                 = errors.New("Token expired")
)

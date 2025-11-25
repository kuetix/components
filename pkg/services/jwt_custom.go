package services

import "github.com/golang-jwt/jwt/v5"

type JwtCustomClaims struct {
	ID string `json:"id"`
	jwt.RegisteredClaims
}

type JwtCustomRefreshClaims struct {
	ID string `json:"id"`
	jwt.RegisteredClaims
}

func (j JwtCustomClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return j.RegisteredClaims.ExpiresAt, nil
}

func (j JwtCustomClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return j.RegisteredClaims.IssuedAt, nil
}

func (j JwtCustomClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return j.RegisteredClaims.NotBefore, nil
}

func (j JwtCustomClaims) GetIssuer() (string, error) {
	return j.RegisteredClaims.Issuer, nil
}

func (j JwtCustomClaims) GetSubject() (string, error) {
	return j.RegisteredClaims.Subject, nil
}

func (j JwtCustomClaims) GetAudience() (jwt.ClaimStrings, error) {
	return j.RegisteredClaims.Audience, nil
}

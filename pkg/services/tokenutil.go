package services

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kuetix/cryptor"
)

func CreateAccessToken(jwtIssuer, encryptedId, secret string, expiry int) (accessToken string, err error) {
	exp := time.Now().Add(time.Hour * time.Duration(expiry))

	claims := &JwtCustomClaims{
		ID: encryptedId,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			ExpiresAt: &jwt.NumericDate{Time: exp},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return t, err
}

func CreateRefreshToken(jwtIssuer, encryptedId, secret string, expiry int) (refreshToken string, err error) {
	claimsRefresh := &JwtCustomRefreshClaims{
		ID: encryptedId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(time.Hour * time.Duration(expiry))},
			Issuer:    jwtIssuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsRefresh)
	rt, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return rt, err
}

//goland:noinspection GoUnusedExportedFunction
func IsAuthorized(requestToken string, secret string) (bool, error) {
	_, err := jwt.Parse(requestToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

//goland:noinspection GoUnusedExportedFunction
func ExtractIDFromToken(cryptor *cryptor.Cryptor, requestToken string, secret string) (string, error) {
	token, err := jwt.Parse(requestToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok && !token.Valid {
		return "", fmt.Errorf("invalid Token")
	}

	ciphertext, err := interfaceToString(claims["id"])
	if err != nil {
		return "", err
	}

	cryptor.SetSecret(secret)
	userId, err := cryptor.DecryptAESBase64(ciphertext)
	// userId, err := cryptor.DecryptBase64(ciphertext)

	return userId, err
}

//goland:noinspection GoUnusedExportedFunction
func ExtractBase64IdFromToken(requestToken string, secret string) (string, error) {
	token, err := jwt.Parse(requestToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok && !token.Valid {
		return "", fmt.Errorf("invalid Token")
	}

	ciphertext, err := interfaceToString(claims["id"])
	if err != nil {
		return "", err
	}

	return ciphertext, err
}

func interfaceToString(textInterface interface{}) (text string, err error) {
	if bytes, ok := textInterface.([]byte); ok {
		text = string(bytes)
	} else {
		if text, ok = textInterface.(string); ok != true {
			return "", fmt.Errorf("textInterface is not a []byte or string")
		}
	}

	return text, nil
}

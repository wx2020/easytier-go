// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package uptime

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Simple HS256 JWT without external deps, compatible with Rust jsonwebtoken default.

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func signHS256(header, payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	return base64URLEncode(mac.Sum(nil))
}

// GenerateAdminToken creates JWT.
func GenerateAdminToken(secret string, exp time.Time) (string, error) {
	h := jwtHeader{Alg: "HS256", Typ: "JWT"}
	hb, _ := json.Marshal(h)
	c := jwtClaims{Sub: "admin", Exp: exp.Unix(), Iat: time.Now().Unix()}
	cb, _ := json.Marshal(c)
	hs := base64URLEncode(hb)
	ps := base64URLEncode(cb)
	sig := signHS256(hs, ps, secret)
	return hs + "." + ps + "." + sig, nil
}

// VerifyAdminToken checks Authorization Bearer token.
func VerifyAdminToken(authHeader, secret string) error {
	token := strings.TrimSpace(authHeader)
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}
	expectedSig := signHS256(parts[0], parts[1], secret)
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return fmt.Errorf("invalid signature")
	}
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return err
	}
	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return err
	}
	if time.Now().Unix() > claims.Exp {
		return fmt.Errorf("token expired")
	}
	if claims.Sub != "admin" {
		return fmt.Errorf("invalid subject")
	}
	return nil
}

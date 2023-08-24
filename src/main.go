package main

import (
	"aidanwoods.dev/go-paseto"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"log"
	"time"
)

func issuer(c string) string {
	return fmt.Sprintf("https://localhost%s", c)
}

func pasetos() {
	// implement go-paseto
	token := paseto.NewToken()

	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(time.Now().Add(2 * time.Hour))
	token.SetString("user-id", "1")

	// encrypt v4.local.xx [basic encrypt]
	key := paseto.NewV4SymmetricKey() // don't share this!!
	encrypted := token.V4Encrypt(key, nil)
	//fmt.Println("private key : ", key)
	fmt.Println("v4.local. : ", encrypted)

	// encrypt v4.public.xx [better]
	//Or sign it (this allows recievers to verify it without sharing secrets)
	secretKey := paseto.NewV4AsymmetricSecretKey() // don't share this!!!
	publicKey := secretKey.Public()                // DO share this one
	signed := token.V4Sign(secretKey, nil)

	//Importing a public key, and then [verifying a token]

	// use public
	parser := paseto.NewParserWithoutExpiryCheck()            // only used because this example token has expired, use NewParser() (which checks expiry by default)
	tokens, _ := parser.ParseV4Public(publicKey, signed, nil) // this will fail if parsing failes, cryptographic checks fail, or validation rules fail

	// use hex
	// decrypt =====
	publicHex := publicKey.ExportHex()
	publicKeys, _ := paseto.NewV4AsymmetricPublicKeyFromHex(publicHex)
	parsers := paseto.NewParser()
	tokenss, _ := parsers.ParseV4Public(publicKeys, signed, nil)

	fmt.Println("==================================")
	fmt.Println("public key token 1 signed : ", signed)
	fmt.Println("public key token1: ", publicKey)
	fmt.Println("info public key token 1 : ", string(tokens.ClaimsJSON()))
	fmt.Println("==================================")
	fmt.Println("public key token 1 signed : ", signed)
	fmt.Println("public key token1 hex: ", publicKey.ExportHex())
	fmt.Println("info public key token 1 hex after decrypt : ", string(tokenss.ClaimsJSON()))
	fmt.Println("==================================")

	//	use basic auth
	//	ref https://github.com/Jonss/jupiter-bank-server

}

func main() {

	// implement jose
	now := time.Now()
	kid := uuid.New().String()

	claim := jwt.Claims{
		Subject:  fmt.Sprintf("%s@clients", kid),
		Issuer:   issuer(fmt.Sprintf(":%v", 3000)),
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(30 * time.Minute)),
	}
	privateCl := struct {
		User   string
		Groups []string
	}{
		"jeff",
		[]string{"foo", "bar"},
	}

	// get signature
	jwtSecretKey := []byte("test")
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS384, Key: jwtSecretKey},
		(&jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": kid}}).WithType("JWT"))
	raw, err := jwt.Signed(sig).Claims(claim).Claims(privateCl).CompactSerialize()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token jwt: ", raw)

	// Parse and decrypt the JWT token
	raws := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTI4NjU2NDQsImh0dHBzOi8vdmF1bHQvZ3JvdXBzIjpbImZvbyIsImJhciJdLCJodHRwczovL3ZhdWx0L3VzZXIiOiJ\nqZWZmIiwiaWF0IjoxNjkyODYzODQ0LCJpc3MiOiJodHRwczovL2xvY2FsaG9zdDozMDAwIiwic3ViIjoiMjkzMTI4OGQtYmU5OS00YmYxLWIzNmItOTBlOGMwNDBiZTc2QGNsaWVudHMifQ.f2pidZV1GGSSv02lv7fdd_O54IGfw3pRKAv1aILndRxGoakUeI4jkbEIOnx4y59G"
	token, err := jwt.ParseSigned(raws)
	if err != nil {
		log.Fatal(err)
	}

	var claims jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		log.Fatal("error getting claims from id token: %w", err)
	}

	err = token.Claims(jwtSecretKey, &claims, &privateCl)
	if err != nil {
		log.Fatal(err)
	}

	// Validate expiration
	err = claims.Validate(jwt.Expected{
		Time: time.Now(),
	})
	if err != nil {
		log.Fatal("Token has expired:", err)
	}

	fmt.Println("Token verified successfully")
	fmt.Println("Token payload (claims):", claims)
	fmt.Println("Token payload (private claims):", privateCl.User)
	fmt.Println("Token  payload without verify: ", claims)
	fmt.Println("Token  payload without verify expired: ", claims.Expiry.Time())
}

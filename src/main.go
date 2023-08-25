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
	parseTokenLocal, _ := paseto.NewParser().ParseV4Local(key, encrypted, nil)

	// encrypt v4.public.xx [better]
	//Or sign it (this allows recievers to verify it without sharing secrets)
	secretKey := paseto.NewV4AsymmetricSecretKey() // don't share this!!!
	signed := token.V4Sign(secretKey, nil)

	//Importing a public key, and then [verifying a token]

	// use public
	publicKey := secretKey.Public()                           // DO share this one
	parser := paseto.NewParserWithoutExpiryCheck()            // only used because this example token has expired, use NewParser() (which checks expiry by default)
	tokens, _ := parser.ParseV4Public(publicKey, signed, nil) // this will fail if parsing failes, cryptographic checks fail, or validation rules fail

	// use hex
	// decrypt =====
	publicHex := publicKey.ExportHex()
	publicHexToDecrypt, _ := paseto.NewV4AsymmetricPublicKeyFromHex(publicHex)
	tokenss, _ := paseto.NewParser().ParseV4Public(publicHexToDecrypt, signed, nil)

	fmt.Println("==================================")
	fmt.Println("============use local=============")
	fmt.Println("==================================")
	fmt.Println("local key token : ", encrypted)
	fmt.Println("local key info key parse : ", string(parseTokenLocal.ClaimsJSON()))
	fmt.Println("==================================")
	fmt.Println("===========use public=============")
	fmt.Println("==================================")
	fmt.Println("public key token : ", signed)
	fmt.Println("public key token hex: ", publicKey.ExportHex())
	fmt.Println("public info key parse: ", string(tokens.ClaimsJSON()))
	fmt.Println("==================================")
	fmt.Println("=============use hex==============")
	fmt.Println("==================================")
	fmt.Println("hex public key token : ", signed)
	fmt.Println("hex public key token hex: ", publicHex)
	fmt.Println("hex public info key parse : ", string(tokenss.ClaimsJSON()))
	fmt.Println("==================================")

	//	use basic auth
	//	ref https://github.com/Jonss/jupiter-bank-server

}

func main() {
	pasetos()
}

func joses() {
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

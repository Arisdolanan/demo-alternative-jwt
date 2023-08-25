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
	token.SetExpiration(time.Now().Add(10 * time.Minute))
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
	exp, _ := tokens.GetExpiration()

	// use hex
	// decrypt =====
	publicHex := publicKey.ExportHex() // DO share this one
	//publicKeyHex, _ := paseto.NewV4AsymmetricPublicKeyFromHex(publicHex)
	//parsedToken, _ := paseto.NewParser().ParseV4Public(publicKeyHex, signed, nil)
	//hexExp, _ := hexTokens.GetExpiration()

	parsers := paseto.NewParser()
	parsers.AddRule(paseto.ForAudience("audience"))
	parsers.AddRule(paseto.IdentifiedBy("identifier"))
	parsers.AddRule(paseto.IssuedBy("issuer"))
	parsers.AddRule(paseto.Subject("subject"))
	parsers.AddRule(paseto.NotExpired())
	parsers.AddRule(paseto.ValidAt(time.Now()))

	//publicHexTemp := "423c5b269e0ef945eba46c509d92015b85f256fa1c5bc2a7fe913d0c3f13e224"
	//signedTemp := "v4.public.eyJleHAiOiIyMDIzLTA4LTI1VDE1OjE3OjQ1KzA3OjAwIiwiaWF0IjoiMjAyMy0wOC0yNVQxNTowNzo0NSswNzowMCIsIm5iZiI6IjIwMjMtMDgtMjVUMTU6MDc6NDUrMDc6MDAiLCJ1c2VyLWlkIjoiMSJ9FQPxkXFs0RYQDPmHVWdGOC0um6mZ9Fgy1tdWWlDl0p05VSh-z7NGbmSk6QR5Mr545usu9SjnB3JjlHckYJtUBw"
	publicKeyHex, _ := paseto.NewV4AsymmetricPublicKeyFromHex(publicHex)
	parsedToken, _ := paseto.NewParser().ParseV4Public(publicKeyHex, signed, nil)
	hexExp, _ := parsedToken.GetExpiration()

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
	fmt.Println("public info key parse exp: ", exp)
	if time.Now().Before(exp) {
		fmt.Println("hex public info key parse exp: success")
	} else {
		fmt.Println("hex public info key parse exp: tidak success")
	}
	fmt.Println("==================================")
	fmt.Println("=============use hex==============")
	fmt.Println("==================================")
	fmt.Println("hex public key token : ", signed)
	fmt.Println("hex public key token hex: ", publicHex)
	fmt.Println("hex public info key parse : ", parsedToken)
	fmt.Println("hex public info key parse : ", string(parsedToken.ClaimsJSON()))
	fmt.Println("public info key parse exp: ", hexExp)
	if time.Now().Before(hexExp) {
		fmt.Println("public info key parse exp: success")
	} else {
		fmt.Println("public info key parse exp: tidak success")
	}
	fmt.Println("==================================")

	// use basic auth
	// ref https://github.com/Jonss/jupiter-bank-server

	// bearer
	// https://github.com/MahdiDelnavazi/golang-monolithic-boilerplate
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

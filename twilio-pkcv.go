package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	//"github.com/twilio/twilio-go"
	//openapi "github.com/twilio/twilio-go/rest/api/v2010"
	"net/url"
)

func main() {
	accountSid := os.Getenv("TWILIO_PKCV_ACCOUNT_SID")
	fmt.Println(accountSid)
	authToken := os.Getenv("TWILIO_PKCV_AUTH_TOKEN")
	fmt.Println(authToken)
	apiKeySid := os.Getenv("TWILIO_PKCV_API_KEY")
	fmt.Println(apiKeySid)
	apiSecret := os.Getenv("TWILIO_PKCV_API_SECRET")
	fmt.Println(apiSecret)
	credentialSid := os.Getenv("TWILIO_PKCV_CREDENTIAL_SID")
	fmt.Print(credentialSid)

	/*
	client := twilio.NewRestClientWithParams(twilio.RestClientParams{
		Username: accountSid,
		Password: authToken,
	})

	params := &openapi.CreateMessageParams{}
	params.SetTo("+14402206699")
	params.SetFrom("+14632238785")
	params.SetBody("Hello from Go!")

	resp, err := client.ApiV2010.CreateMessage(params)
	if err != nil {
		fmt.Println(err.Error())
		err = nil
	} else {
		fmt.Println("Message Sid: " + *resp.Sid)
	}
	 */

	//endpoint := "https://twlo.ngrok.io"
	endpoint := "https://api.twilio.com/2010-04-01/Accounts/" + accountSid + "/Messages.json"
	data := url.Values{}
	data.Set("From", "+14632238785")
	data.Set("To", "+14402206699")
	data.Set("Body", "Hello from Go!")

	client := &http.Client{}
	r, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	hrh := "authorization;host"
	authorization := "Basic " + basicAuth(apiKeySid, apiSecret)
	host := r.Host

	// hrh - "authorization;host"

	// Canonical reuqest values
	log.Println("HTTP Method: ", r.Method)
	log.Println("Host: ", host)
	log.Println("URI: ", r.URL.RequestURI())

	log.Println("Query String: N/A (no query strings for POST request)")
	log.Println("Authorization: ", authorization)
	log.Println("Request body: ", data.Encode())
	sum := sha256.Sum256([]byte(data.Encode()))
	hashedRequestBody := fmt.Sprintf("%x", sum)
	log.Println("Hex(SHA256(request body): ", hashedRequestBody)
	log.Println(r.URL.Query())

	// Set headers
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Authorization", authorization)

	finalConanoicalRequest :=
		r.Method + "\n" +
		r.URL.RequestURI() + "\n" +
		"" + "\n" /* query string */ +
		"authorization:" + authorization + "\n" +
		"host:" + host + "\n" +
		"\n" /* header termination */ +
	    hrh + "\n" +
		hashedRequestBody

	fmt.Println(finalConanoicalRequest)
	fmt.Println()
	hashedSignature := fmt.Sprintf("%x", sha256.Sum256([]byte(finalConanoicalRequest)))
	fmt.Println(hashedSignature)

	// Generate the JWT
	// Load key
	usr, _ := user.Current()
	dir := usr.HomeDir
	privateKeyData, err := ioutil.ReadFile(filepath.Join(dir, ".ssh/twilio_private_key_nopass.pem"))
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(privateKeyData)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	fmt.Println(key.N)

	// Create the JWT
	type TwilioClaims struct {
		HeadersHash string `json:"hrh"`
		RequestHash string `json:"rqh"`
		jwt.StandardClaims
	}

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header = make(map[string]interface{})
	token.Header["cty"] = "twilio-pkrv;v=1"
	token.Header["typ"] = "JWT"
	token.Header["alg"] = "RS256"
	token.Header["kid"] = credentialSid

	currentTimestamp := time.Now().Unix()
	token.Claims = TwilioClaims{
		HeadersHash: hrh,
		RequestHash: hashedSignature,
		StandardClaims: jwt.StandardClaims{
			Issuer:    apiKeySid,
			Subject:   accountSid,
			NotBefore: currentTimestamp,
			ExpiresAt: currentTimestamp + 300,
		},
	}
	signedString, err := token.SignedString(key)
	fmt.Printf("%v %v", signedString, err)

	// Add the JWT to the request header
	r.Header.Add("Twilio-Client-Validation", signedString)

	// Send the request
	res, err := client.Do(r)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(res.Status)
	defer res.Body.Close()

	// Response
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Println()
	log.Println(string(body))
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

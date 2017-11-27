// Copyright 2017 Darren Gibb
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package masterpassword provides passwords as defined by the system defined at https://masterpasswordapp.com/
package masterpassword // import "github.com/afterecho/masterpassword/masterpassword"

import (
	"golang.org/x/crypto/scrypt"
	"crypto/hmac"
	"crypto/sha256"
	"bytes"
	"encoding/binary"
	"fmt"
)

// Library version
const VERSION = "1.0.0"

const mpN = 32768
const mpR = 8
const mpP = 2
const mpDkLen = 64

var characterMap = map[rune]string{
	'V': "AEIOU",
	'C': "BCDFGHJKLMNPQRSTVWXYZ",
	'A': "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
	'v': "aeiou",
	'c': "bcdfghjklmnpqrstvwxyz",
	'a': "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
	'n': "0123456789",
	'o': "@&%?,=[]_:-+*$#!'^~;()/.",
	'x': "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()"}

type Template struct {
	maps []string
	// English description of the password output
	Description string
}

var templateMap = map[string]Template{
	"x": {[]string{"anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"}, "20 characters, contains symbols"},
	"l": {[]string{"CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno", "CvccnoCvcvCvcv",
		"CvccCvcvnoCvcv", "CvccCvcvCvcvno", "CvcvnoCvccCvcv", "CvcvCvccnoCvcv",
		"CvcvCvccCvcvno", "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno",
		"CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno", "CvcvnoCvccCvcc",
		"CvcvCvccnoCvcc", "CvcvCvccCvccno", "CvccnoCvcvCvcc", "CvccCvcvnoCvcc",
		"CvccCvcvCvccno"}, "Copy-friendly, 14 characters, symbols"},
	"m": {[]string{"CvcnoCvc", "CvcCvcno"}, "Copy-friendly, 8 characters, symbols"},
	"s": {[]string{"Cvcn"}, "Copy-friendly, 4 characters, no symbols"},
	"b": {[]string{"aaanaaan", "aannaaan", "aaannaaa"}, "8 characters, no symbols"},
	"i": {[]string{"nnnn"}, "4 numbers"},
	"n": {[]string{"cvccvcvcv"}, "9 letter name"},
	"p": {[]string{"cvcc cvc cvccvcv cvc", "cvc cvccvcvcv cvcv", "cv cvccv cvc cvcvccv"}, "20 character sentence"}}


// GetPasswordTypeMap returns the map of password type codes to use in the Password() function
func GetPasswordTypeMap() map[string]Template{
	return templateMap
}

// Password returns a password using the algorithm at http://masterpasswordapp.com/
// If error is nil a usable password is returned, else the password will be the blank string.
//
// The available values for password_type can be obtained from a call to GetPasswordTypeMap()
func Password(username string, sitename string, siteCounter int, passwordType string, masterPassword []byte) (string, error) {
	if _, ok := templateMap[passwordType]; !ok {
		return "", fmt.Errorf("unknown password type: %s", passwordType)
	}

	constantSaltBytes := []byte("com.lyndir.masterpassword")

	usernameBytes := []byte(username)
	usernameLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(usernameLenBytes, uint32(len(username)))

	var masterSalt []byte
	masterSalt = append(masterSalt, constantSaltBytes...)
	masterSalt = append(masterSalt, usernameLenBytes...)
	masterSalt = append(masterSalt, usernameBytes...)
	masterKey, err := scrypt.Key(masterPassword, masterSalt, mpN, mpR, mpP, mpDkLen)

	if err != nil {
		return "", err
	}

	sitenameBytes := []byte(sitename)
	sitenameLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sitenameLenBytes, uint32(len(sitename)))

	sitenameCounterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sitenameCounterBytes, uint32(siteCounter))

	var sitePasswordInfo []byte
	sitePasswordInfo = append(sitePasswordInfo, constantSaltBytes...)
	sitePasswordInfo = append(sitePasswordInfo, sitenameLenBytes...)
	sitePasswordInfo = append(sitePasswordInfo, sitenameBytes...)
	sitePasswordInfo = append(sitePasswordInfo, sitenameCounterBytes...)

	masterPasswordHmac := hmac.New(sha256.New, masterKey)
	masterPasswordHmac.Write(sitePasswordInfo)

	var message []byte
	message = masterPasswordHmac.Sum(nil)

	templateIndex := int(message[0] & 0xff)

	possibleTemplates := templateMap[passwordType].maps
	template := possibleTemplates[templateIndex%len(possibleTemplates)]

	var passwordBuffer bytes.Buffer

	for i := 0; i < len(template); i++ {
		seedChar := message[i+1] & 0xFF
		templateChar := rune(template[i])
		if templateChar == ' ' {
			passwordBuffer.WriteString(" ")
		} else {
			char := characterMap[templateChar][int(seedChar)%len(characterMap[templateChar])]
			passwordBuffer.WriteString(string(char))
		}
	}

	return passwordBuffer.String(), nil
}

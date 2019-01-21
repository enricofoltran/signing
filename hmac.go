// Copyright 2019 Enrico Foltran. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package signing

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
)

func SaltedHmac(salt, value, secret []byte) []byte {
	dkey := sha1.New()
	dkey.Write(salt)
	dkey.Write(secret)
	key := dkey.Sum(nil)

	hash := hmac.New(sha1.New, key)
	hash.Write(value)
	hashed := hash.Sum(nil)
	return hashed
}

func Base64Hmac(salt, value, key []byte) string {
	return base64.RawURLEncoding.EncodeToString(SaltedHmac(salt, value, key))
}

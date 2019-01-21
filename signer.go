// Copyright 2019 Enrico Foltran. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Utility for creating and restoring url-safe signed JSON objects.
package signing

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type SignUnsigner interface {
	Sign(value string) string
	Unsign(value string) (string, error)
}

type Signer struct {
	key  string
	sep  string
	salt string
}

var (
	unsafeSep = regexp.MustCompile("^[A-z0-9-_=]*$")
)

var (
	ErrInvalidKey            = errors.New("Invalid key: key can not be an empty string")
	ErrInvalidSalt           = errors.New("Invalid salt: salt can not be an empty string")
	ErrUnsafeSignerSeparator = errors.New("Unsafe Signer separator: cannot be empty or consist of only A-z0-9-_=")
	ErrBadSignature          = errors.New("Signature not valid")
)

func NewSigner(key, sep, salt string) (*Signer, error) {
	if strings.TrimSpace(key) == "" {
		return nil, ErrInvalidKey
	}
	if strings.TrimSpace(salt) == "" {
		return nil, ErrInvalidSalt
	}
	sep = strings.TrimSpace(sep)
	if sep == "" {
		sep = ":"
	}
	if match := unsafeSep.MatchString(sep); match {
		return nil, ErrUnsafeSignerSeparator
	}
	return &Signer{
		key:  key,
		sep:  sep,
		salt: salt,
	}, nil
}

func (ps *Signer) signature(value string) string {
	return Base64Hmac([]byte(ps.salt+"signer"), []byte(value), []byte(ps.key))
}

func (ps *Signer) Sign(value string) string {
	return fmt.Sprintf("%s%s%s", value, ps.sep, ps.signature(value))
}

func (ps *Signer) Unsign(signed string) (string, error) {
	idx := strings.LastIndex(signed, ps.sep)
	if idx == -1 {
		return "", ErrBadSignature
	}
	value, signature := signed[:idx], signed[idx+1:]
	computed_signature := ps.signature(value)

	if eq := subtle.ConstantTimeCompare([]byte(signature), []byte(computed_signature)); eq == 1 {
		return value, nil
	} else {
		return "", ErrBadSignature
	}
}

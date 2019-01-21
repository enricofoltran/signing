// Copyright 2019 Enrico Foltran. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package signing

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/enricofoltran/baseconv"
)

var (
	ErrSignatureExpired = errors.New("Signature expired")
)

type TimestampSigner struct {
	Signer
}

func NewTimestampSigner(key, sep, salt string) (*TimestampSigner, error) {
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
	return &TimestampSigner{Signer{
		key:  key,
		sep:  sep,
		salt: salt,
	}}, nil
}

func (ts *TimestampSigner) timestamp() string {
	return baseconv.Base62.Encode(time.Now().Unix())
}

func (ts *TimestampSigner) Sign(value string) string {
	value = fmt.Sprintf("%s%s%s", value, ts.sep, ts.timestamp())
	signature := ts.signature(value)
	return fmt.Sprintf("%s%s%s", value, ts.sep, signature)
}

func (ts *TimestampSigner) UnsignMaxAge(signed string, maxAge time.Duration) (string, error) {
	value, err := ts.Unsign(signed)
	if err != nil {
		return "", err
	}

	idx := strings.LastIndex(value, ts.sep)
	if idx == -1 {
		return "", ErrBadSignature
	}

	value, timestamp := value[:idx], value[idx+1:]
	decoded_timestamp, err := baseconv.Base62.Decode(timestamp)
	if err != nil {
		return "", ErrBadSignature
	}

	issued_time := time.Unix(decoded_timestamp, 0)
	age := time.Now().Sub(issued_time)
	if age > maxAge {
		return "", ErrSignatureExpired
	}

	return value, nil
}

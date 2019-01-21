**WARNING! This repo is a work in progress, things may be broken, api will change, tests and documentation are missing.**

# Signing
Utility for creating and restoring url-safe signed JSON objects.

Based on Django's [signing.py](https://github.com/django/django/blob/master/django/core/signing.py) utility.

## Documentation
Read the [documentation](https://godoc.org/github.com/enricofoltran/signing) at godoc.org.

## Usage
```go
func ExampleNewSigner() {
	var key string = "v5kyWAnOBiEKVpAZmMC03BY18Fi6u1ALuZZUb0gnU7Q="
	var salt string = "Gm8uSwfozUKXXatEJLpBB1cNq0F0AR1U7LRaqeO+Tn8="
	var sep string = ":"

	signer, err := signing.NewSigner(key, sep, salt)
	if err != nil {
		panic(err)
	}

	signed := signer.Sign("the-quick-brown-fox")
	fmt.Print(signed)

	unsigned, err := signer.Unsign(signed)
	switch err {
	case signing.ErrBadSignature:
		fmt.Printf("Unsign error: %v", err)
	default:
		panic(err)
	}
	fmt.Print(unsigned)

	// Output:
	// the-quick-brown-fox:-maTzDzCZGpiiLqm6SZr0KkMfBo
}
```
package model

import "errors"

//Credential errors collection
var (
	ErrCredentialEmailEmpty     = errors.New("Credential email cannot be empty")
	ErrCredentialEmailMalformed = errors.New("Credential email is not a valid email address")
	ErrCredentialPassNotMatch   = errors.New("Credential password does not match")
	ErrCredentialProviderEmpty  = errors.New("Credential provider cannot be empty")
)

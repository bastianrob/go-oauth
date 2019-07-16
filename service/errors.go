package service

import "errors"

//Error collection
var (
	ErrNotFound       = errors.New("Object not found")
	ErrAlreadyExists  = errors.New("Object already exists")
	ErrNotImplemented = errors.New("Not implemented")
)

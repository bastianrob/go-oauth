// Code generated by moq; DO NOT EDIT.
// github.com/matryer/moq

package mock

import (
	"context"
	"sync"

	"github.com/bastianrob/go-oauth/model"
)

var (
	lockCredentialRepoMockCount  sync.RWMutex
	lockCredentialRepoMockCreate sync.RWMutex
	lockCredentialRepoMockGet    sync.RWMutex
	lockCredentialRepoMockUpdate sync.RWMutex
)

// CredentialRepoMock is a mock implementation of CredentialRepo.
//
//     func TestSomethingThatUsesCredentialRepo(t *testing.T) {
//
//         // make and configure a mocked CredentialRepo
//         mockedCredentialRepo := &CredentialRepoMock{
//             CountFunc: func(ctx context.Context, email string) int {
// 	               panic("mock out the Count method")
//             },
//             CreateFunc: func(ctx context.Context, cred model.Credential) error {
// 	               panic("mock out the Create method")
//             },
//             GetFunc: func(ctx context.Context, email string) (model.Credential, error) {
// 	               panic("mock out the Get method")
//             },
//             UpdateFunc: func(ctx context.Context, email string, cred model.Credential) (model.Credential, error) {
// 	               panic("mock out the Update method")
//             },
//         }
//
//         // use mockedCredentialRepo in code that requires CredentialRepo
//         // and then make assertions.
//
//     }
type CredentialRepoMock struct {
	// CountFunc mocks the Count method.
	CountFunc func(ctx context.Context, email string) int

	// CreateFunc mocks the Create method.
	CreateFunc func(ctx context.Context, cred model.Credential) error

	// GetFunc mocks the Get method.
	GetFunc func(ctx context.Context, email string) (model.Credential, error)

	// UpdateFunc mocks the Update method.
	UpdateFunc func(ctx context.Context, email string, cred model.Credential) (model.Credential, error)

	// calls tracks calls to the methods.
	calls struct {
		// Count holds details about calls to the Count method.
		Count []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Email is the email argument value.
			Email string
		}
		// Create holds details about calls to the Create method.
		Create []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Cred is the cred argument value.
			Cred model.Credential
		}
		// Get holds details about calls to the Get method.
		Get []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Email is the email argument value.
			Email string
		}
		// Update holds details about calls to the Update method.
		Update []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Email is the email argument value.
			Email string
			// Cred is the cred argument value.
			Cred model.Credential
		}
	}
}

// Count calls CountFunc.
func (mock *CredentialRepoMock) Count(ctx context.Context, email string) int {
	if mock.CountFunc == nil {
		panic("CredentialRepoMock.CountFunc: method is nil but CredentialRepo.Count was just called")
	}
	callInfo := struct {
		Ctx   context.Context
		Email string
	}{
		Ctx:   ctx,
		Email: email,
	}
	lockCredentialRepoMockCount.Lock()
	mock.calls.Count = append(mock.calls.Count, callInfo)
	lockCredentialRepoMockCount.Unlock()
	return mock.CountFunc(ctx, email)
}

// CountCalls gets all the calls that were made to Count.
// Check the length with:
//     len(mockedCredentialRepo.CountCalls())
func (mock *CredentialRepoMock) CountCalls() []struct {
	Ctx   context.Context
	Email string
} {
	var calls []struct {
		Ctx   context.Context
		Email string
	}
	lockCredentialRepoMockCount.RLock()
	calls = mock.calls.Count
	lockCredentialRepoMockCount.RUnlock()
	return calls
}

// Create calls CreateFunc.
func (mock *CredentialRepoMock) Create(ctx context.Context, cred model.Credential) error {
	if mock.CreateFunc == nil {
		panic("CredentialRepoMock.CreateFunc: method is nil but CredentialRepo.Create was just called")
	}
	callInfo := struct {
		Ctx  context.Context
		Cred model.Credential
	}{
		Ctx:  ctx,
		Cred: cred,
	}
	lockCredentialRepoMockCreate.Lock()
	mock.calls.Create = append(mock.calls.Create, callInfo)
	lockCredentialRepoMockCreate.Unlock()
	return mock.CreateFunc(ctx, cred)
}

// CreateCalls gets all the calls that were made to Create.
// Check the length with:
//     len(mockedCredentialRepo.CreateCalls())
func (mock *CredentialRepoMock) CreateCalls() []struct {
	Ctx  context.Context
	Cred model.Credential
} {
	var calls []struct {
		Ctx  context.Context
		Cred model.Credential
	}
	lockCredentialRepoMockCreate.RLock()
	calls = mock.calls.Create
	lockCredentialRepoMockCreate.RUnlock()
	return calls
}

// Get calls GetFunc.
func (mock *CredentialRepoMock) Get(ctx context.Context, email string) (model.Credential, error) {
	if mock.GetFunc == nil {
		panic("CredentialRepoMock.GetFunc: method is nil but CredentialRepo.Get was just called")
	}
	callInfo := struct {
		Ctx   context.Context
		Email string
	}{
		Ctx:   ctx,
		Email: email,
	}
	lockCredentialRepoMockGet.Lock()
	mock.calls.Get = append(mock.calls.Get, callInfo)
	lockCredentialRepoMockGet.Unlock()
	return mock.GetFunc(ctx, email)
}

// GetCalls gets all the calls that were made to Get.
// Check the length with:
//     len(mockedCredentialRepo.GetCalls())
func (mock *CredentialRepoMock) GetCalls() []struct {
	Ctx   context.Context
	Email string
} {
	var calls []struct {
		Ctx   context.Context
		Email string
	}
	lockCredentialRepoMockGet.RLock()
	calls = mock.calls.Get
	lockCredentialRepoMockGet.RUnlock()
	return calls
}

// Update calls UpdateFunc.
func (mock *CredentialRepoMock) Update(ctx context.Context, email string, cred model.Credential) (model.Credential, error) {
	if mock.UpdateFunc == nil {
		panic("CredentialRepoMock.UpdateFunc: method is nil but CredentialRepo.Update was just called")
	}
	callInfo := struct {
		Ctx   context.Context
		Email string
		Cred  model.Credential
	}{
		Ctx:   ctx,
		Email: email,
		Cred:  cred,
	}
	lockCredentialRepoMockUpdate.Lock()
	mock.calls.Update = append(mock.calls.Update, callInfo)
	lockCredentialRepoMockUpdate.Unlock()
	return mock.UpdateFunc(ctx, email, cred)
}

// UpdateCalls gets all the calls that were made to Update.
// Check the length with:
//     len(mockedCredentialRepo.UpdateCalls())
func (mock *CredentialRepoMock) UpdateCalls() []struct {
	Ctx   context.Context
	Email string
	Cred  model.Credential
} {
	var calls []struct {
		Ctx   context.Context
		Email string
		Cred  model.Credential
	}
	lockCredentialRepoMockUpdate.RLock()
	calls = mock.calls.Update
	lockCredentialRepoMockUpdate.RUnlock()
	return calls
}

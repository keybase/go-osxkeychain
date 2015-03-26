package osxkeychain

/*
#cgo CFLAGS: -mmacosx-version-min=10.6 -D__MAC_OS_X_VERSION_MAX_ALLOWED=1060
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type GenericPassword struct {
	ServiceName string
	AccountName string
	Password    string
}

type _OSStatus C.OSStatus

// TODO: Fill this out.
const (
	errDuplicateItem _OSStatus = C.errSecDuplicateItem
)

type keychainError struct {
	errCode C.OSStatus
}

func newKeychainError(errCode C.OSStatus) error {
	if errCode == C.noErr {
		return nil
	}
	return &keychainError{errCode}
}

func (ke *keychainError) getErrCode() _OSStatus {
	return _OSStatus(ke.errCode)
}

func (ke *keychainError) Error() string {
	errorMessageCFString := C.SecCopyErrorMessageString(ke.errCode, nil)
	defer C.CFRelease(C.CFTypeRef(errorMessageCFString))

	errorMessageCString := C.CFStringGetCStringPtr(errorMessageCFString, C.kCFStringEncodingASCII)

	if errorMessageCString != nil {
		return C.GoString(errorMessageCString)
	}

	return fmt.Sprintf("keychainError with unknown error code %d", ke.errCode)
}

func AddGenericPassword(pass *GenericPassword) error {
	// TODO: Encode in UTF-8 first.
	// TODO: Check for length overflowing 32 bits.
	serviceName := C.CString(pass.ServiceName)
	defer C.free(unsafe.Pointer(serviceName))

	// TODO: Encode in UTF-8 first.
	// TODO: Check for length overflowing 32 bits.
	accountName := C.CString(pass.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	// TODO: Check for length overflowing 32 bits.
	password := C.CString(pass.Password)
	defer C.free(unsafe.Pointer(password))

	errCode := C.SecKeychainAddGenericPassword(
		nil, // default keychain
		C.UInt32(len(pass.ServiceName)),
		serviceName,
		C.UInt32(len(pass.AccountName)),
		accountName,
		C.UInt32(len(pass.Password)),
		unsafe.Pointer(password),
		nil,
	)

	return newKeychainError(errCode)
}

func FindGenericPassword(pass *GenericPassword) (*GenericPassword, error) {
	// TODO: Encode in UTF-8 first.
	// TODO: Check for length overflowing 32 bits.
	serviceName := C.CString(pass.ServiceName)
	defer C.free(unsafe.Pointer(serviceName))

	// TODO: Encode in UTF-8 first.
	// TODO: Check for length overflowing 32 bits.
	accountName := C.CString(pass.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	var passwordLength C.UInt32

	var password unsafe.Pointer

	errCode := C.SecKeychainFindGenericPassword(
		nil, // default keychain
		C.UInt32(len(pass.ServiceName)),
		serviceName,
		C.UInt32(len(pass.AccountName)),
		accountName,
		&passwordLength,
		&password,
		nil,
	)

	if ke := newKeychainError(errCode); ke != nil {
		return nil, ke
	}

	defer C.SecKeychainItemFreeContent(nil, password)

	resp := *pass
	resp.Password = C.GoStringN((*C.char)(password), C.int(passwordLength))

	return &resp, nil
}

func FindAndRemoveGenericPassword(pass *GenericPassword) error {
	var itemRef C.SecKeychainItemRef

	errCode := C.SecKeychainFindGenericPassword(
		nil, // default keychain
		C.UInt32(len(pass.ServiceName)),
		C.CString(pass.ServiceName),
		C.UInt32(len(pass.AccountName)),
		C.CString(pass.AccountName),
		nil,
		nil,
		&itemRef,
	)

	if ke := newKeychainError(errCode); ke != nil {
		return ke
	}

	defer C.CFRelease(C.CFTypeRef(itemRef))

	errCode = C.SecKeychainItemDelete(itemRef)
	return newKeychainError(errCode)

	return nil
}

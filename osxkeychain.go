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

// All string fields must have size that fits in 32 bits. All string
// fields except for Password must be encoded in UTF-8.
type GenericPasswordAttributes struct {
	ServiceName string
	AccountName string
	Password    string
}

type keychainError C.OSStatus

// Error codes from https://developer.apple.com/library/mac/documentation/security/Reference/keychainservices/Reference/reference.html#//apple_ref/doc/uid/TP30000898-CH5g-CJBEABHG
const (
	ErrUnimplemented     keychainError = C.errSecUnimplemented
	ErrParam             keychainError = C.errSecParam
	ErrAllocate          keychainError = C.errSecAllocate
	ErrNotAvailable      keychainError = C.errSecNotAvailable
	ErrReadOnly          keychainError = C.errSecReadOnly
	ErrAuthFailed        keychainError = C.errSecAuthFailed
	ErrNoSuchKeychain    keychainError = C.errSecNoSuchKeychain
	ErrInvalidKeychain   keychainError = C.errSecInvalidKeychain
	ErrDuplicateKeychain keychainError = C.errSecDuplicateKeychain
	ErrDuplicateCallback keychainError = C.errSecDuplicateCallback
	ErrInvalidCallback   keychainError = C.errSecInvalidCallback
	ErrDuplicateItem     keychainError = C.errSecDuplicateItem
	ErrItemNotFound      keychainError = C.errSecItemNotFound
	ErrBufferTooSmall    keychainError = C.errSecBufferTooSmall
	ErrDataTooLarge      keychainError = C.errSecDataTooLarge
	ErrNoSuchAttr        keychainError = C.errSecNoSuchAttr
	ErrInvalidItemRef    keychainError = C.errSecInvalidItemRef
	ErrInvalidSearchRef  keychainError = C.errSecInvalidSearchRef
	ErrNoSuchClass       keychainError = C.errSecNoSuchClass
	ErrNoDefaultKeychain keychainError = C.errSecNoDefaultKeychain
	ErrReadOnlyAttr      keychainError = C.errSecReadOnlyAttr
	// TODO: Fill out more of these?
)

func newKeychainError(errCode C.OSStatus) error {
	if errCode == C.noErr {
		return nil
	}
	return keychainError(errCode)
}

func (ke keychainError) Error() string {
	errorMessageCFString := C.SecCopyErrorMessageString(C.OSStatus(ke), nil)
	defer C.CFRelease(C.CFTypeRef(errorMessageCFString))

	errorMessageCString := C.CFStringGetCStringPtr(errorMessageCFString, C.kCFStringEncodingASCII)

	if errorMessageCString != nil {
		return C.GoString(errorMessageCString)
	}

	return fmt.Sprintf("keychainError with unknown error code %d", C.OSStatus(ke))
}

func AddGenericPassword(attributes *GenericPasswordAttributes) error {
	// TODO: Check fields for UTF-8 encoding and size fitting in
	// 32 bits.
	serviceName := C.CString(attributes.ServiceName)
	defer C.free(unsafe.Pointer(serviceName))

	accountName := C.CString(attributes.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	password := unsafe.Pointer(C.CString(attributes.Password))
	defer C.free(password)

	errCode := C.SecKeychainAddGenericPassword(
		nil, // default keychain
		C.UInt32(len(attributes.ServiceName)),
		serviceName,
		C.UInt32(len(attributes.AccountName)),
		accountName,
		C.UInt32(len(attributes.Password)),
		password,
		nil,
	)

	return newKeychainError(errCode)
}

func FindGenericPassword(attributes *GenericPasswordAttributes) (string, error) {
	// TODO: Check fields for UTF-8 encoding and size fitting in
	// 32 bits.
	serviceName := C.CString(attributes.ServiceName)
	defer C.free(unsafe.Pointer(serviceName))

	accountName := C.CString(attributes.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	var passwordLength C.UInt32

	var password unsafe.Pointer

	errCode := C.SecKeychainFindGenericPassword(
		nil, // default keychain
		C.UInt32(len(attributes.ServiceName)),
		serviceName,
		C.UInt32(len(attributes.AccountName)),
		accountName,
		&passwordLength,
		&password,
		nil,
	)

	if err := newKeychainError(errCode); err != nil {
		return "", err
	}

	defer C.SecKeychainItemFreeContent(nil, password)

	return C.GoStringN((*C.char)(password), C.int(passwordLength)), nil
}

func FindAndRemoveGenericPassword(attributes *GenericPasswordAttributes) error {
	itemRef, err := findGenericPasswordItem(attributes)
	if err != nil {
		return err
	}

	defer C.CFRelease(C.CFTypeRef(itemRef))

	errCode := C.SecKeychainItemDelete(itemRef)
	return newKeychainError(errCode)
}

func ReplaceOrAddGenericPassword(attributes *GenericPasswordAttributes) error {
	itemRef, err := findGenericPasswordItem(attributes)
	if err == ErrItemNotFound {
		return AddGenericPassword(attributes)
	} else if err != nil {
		return err
	}

	defer C.CFRelease(C.CFTypeRef(itemRef))

	// TODO: Check for size fitting in 32 bits.
	password := unsafe.Pointer(C.CString(attributes.Password))
	defer C.free(password)

	errCode := C.SecKeychainItemModifyAttributesAndData(
		itemRef,
		nil,
		C.UInt32(len(attributes.Password)),
		password,
	)

	return newKeychainError(errCode)
}

func findGenericPasswordItem(attributes *GenericPasswordAttributes) (itemRef C.SecKeychainItemRef, err error) {
	// TODO: Check field for UTF-8 encoding and size fitting in 32
	// bits.
	serviceName := C.CString(attributes.ServiceName)
	defer C.free(unsafe.Pointer(serviceName))

	accountName := C.CString(attributes.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	errCode := C.SecKeychainFindGenericPassword(
		nil, // default keychain
		C.UInt32(len(attributes.ServiceName)),
		serviceName,
		C.UInt32(len(attributes.AccountName)),
		accountName,
		nil,
		nil,
		&itemRef,
	)

	err = newKeychainError(errCode)
	return
}

package osxkeychain

import (
	"testing"
)

func TestGenericPassword(t *testing.T) {
	passwordVal := "longfakepassword"
	accountNameVal := "bgentry"
	serviceNameVal := "osxkeychain"
	blankPass := GenericPassword{
		ServiceName: serviceNameVal,
		AccountName: accountNameVal,
	}
	// Add the blank password
	err := AddGenericPassword(&blankPass)
	if err != nil {
		t.Error(err)
	}

	pass := GenericPassword{
		ServiceName: serviceNameVal,
		AccountName: accountNameVal,
		Password: passwordVal,
	}

	// Try adding again, expect it to fail as a duplicate
	err = AddGenericPassword(&pass)
	if ke, ok := err.(*keychainError); !ok || ke.getErrCode() != errDuplicateItem {
		t.Errorf("expected ErrDuplicateItem on 2nd save, got %s", err)
	}

	// Find the password
	pass2 := GenericPassword{
		ServiceName: serviceNameVal,
		AccountName: accountNameVal,
	}
	resp, err := FindGenericPassword(&pass2)
	if err != nil {
		t.Error(err)
	}
	if resp.Password != "" {
		t.Errorf("FindGenericPassword expected Password=%q, got %q", "", resp.Password)
	}
	if resp.AccountName != accountNameVal {
		t.Errorf("FindGenericPassword expected AccountName=%q, got %q", accountNameVal, resp.AccountName)
	}
	if resp.ServiceName != serviceNameVal {
		t.Errorf("FindGenericPassword expected ServiceName=%q, got %q", serviceNameVal, resp.ServiceName)
	}

	// Replace password.
	err = ReplaceOrAddGenericPassword(&pass)
	if err != nil {
		t.Error(err)
	}

	// Find the password again.
	pass2 = GenericPassword{
		ServiceName: serviceNameVal,
		AccountName: accountNameVal,
	}
	resp, err = FindGenericPassword(&pass2)
	if err != nil {
		t.Error(err)
	}
	if resp.Password != passwordVal {
		t.Errorf("FindGenericPassword expected Password=%q, got %q", passwordVal, resp.Password)
	}
	if resp.AccountName != accountNameVal {
		t.Errorf("FindGenericPassword expected AccountName=%q, got %q", accountNameVal, resp.AccountName)
	}
	if resp.ServiceName != serviceNameVal {
		t.Errorf("FindGenericPassword expected ServiceName=%q, got %q", serviceNameVal, resp.ServiceName)
	}

	err = FindAndRemoveGenericPassword(&pass2)
	if err != nil {
		t.Error(err)
	}

	// Try removing a nonexistent password.
	err = FindAndRemoveGenericPassword(&pass2)
	if ke, ok := err.(*keychainError); !ok || ke.getErrCode() != errItemNotFound {
		t.Errorf("expected ErrItemNotFound on 2nd removal, got %s", err)
	}
}

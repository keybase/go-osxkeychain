package osxkeychain

import (
	"testing"
)

func TestGenericPassword(t *testing.T) {
	passwordVal := "longfakepassword"
	accountNameVal := "bgentry"
	serviceNameVal := "osxkeychain"
	pass := GenericPassword{
		ServiceName:     serviceNameVal,
		AccountName:    accountNameVal,
		Password: passwordVal,
	}
	// Add the password
	err := AddGenericPassword(&pass)
	if err != nil {
		t.Error(err)
	}
	// Try adding again, expect it to fail as a duplicate
	err = AddGenericPassword(&pass)
	if err != ErrDuplicateItem {
		t.Errorf("expected ErrDuplicateItem on 2nd save, got %s", err)
	}
	// Find the password
	pass2 := GenericPassword{
		ServiceName: serviceNameVal,
		AccountName:    accountNameVal,
	}
	resp, err := FindGenericPassword(&pass2)
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
}

func TestInternetPassword(t *testing.T) {
	passwordVal := "longfakepassword with \000 embedded nuls \000"
	accountNameVal := "bgentry"
	serverNameVal := "api.heroku.com"
	securityDomainVal := ""
	// 	portVal := 886
	pathVal := "/fake"
	pass := InternetPassword{
		ServerName:     serverNameVal,
		SecurityDomain: securityDomainVal,
		AccountName:    accountNameVal,
		// 		Port:           portVal,
		Path:     pathVal,
		Protocol: ProtocolHTTPS,
		AuthType: AuthenticationHTTPBasic,
		Password: passwordVal,
	}
	// Add the password
	err := AddInternetPassword(&pass)
	if err != nil {
		t.Error(err)
	}
	// Try adding again, expect it to fail as a duplicate
	err = AddInternetPassword(&pass)
	if ke, ok := err.(*keychainError); !ok || ke.getErrCode() != errDuplicateItem {
		t.Errorf("expected ErrDuplicateItem on 2nd save, got %s", err)
	}
	// Find the password
	pass2 := InternetPassword{
		ServerName: "api.heroku.com",
		Path:       pathVal,
		Protocol:   ProtocolHTTPS,
		AuthType:   AuthenticationHTTPBasic,
	}
	resp, err := FindInternetPassword(&pass2)
	if err != nil {
		t.Error(err)
	}
	if resp.Password != passwordVal {
		t.Errorf("FindInternetPassword expected Password=%s, got %s", passwordVal, resp.Password)
	}
	if resp.AccountName != accountNameVal {
		t.Errorf("FindInternetPassword expected AccountName=%q, got %q", accountNameVal, resp.AccountName)
	}
	if resp.ServerName != serverNameVal {
		t.Errorf("FindInternetPassword expected ServerName=%q, got %q", serverNameVal, resp.ServerName)
	}
	if resp.SecurityDomain != securityDomainVal {
		t.Errorf("FindInternetPassword expected SecurityDomain=%q, got %q", securityDomainVal, resp.SecurityDomain)
	}
	if resp.Protocol != ProtocolHTTPS {
		t.Errorf("FindInternetPassword expected Protocol=https, got %q", resp.Protocol)
	}
	// 	if resp.Port != portVal {
	// 		t.Errorf("FindInternetPassword expected Port=%d, got %d", portVal, resp.Port)
	// 	}
	if resp.AuthType != AuthenticationHTTPBasic {
		t.Errorf("FindInternetPassword expected AuthType=HTTPBasic, got %q", resp.AuthType)
	}
	if resp.Path != pathVal {
		t.Errorf("FindInternetPassword expected Path=%q, got %q", pathVal, resp.Path)
	}
}

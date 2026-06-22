package kubeconfig

import (
	"encoding/base64"
	"testing"
)

func TestCAFromKubeconfigSecret(t *testing.T) {
	kubeconfig := `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: QkFTRTY0Q0E=
    server: https://1.2.3.4:6443
  name: demo
`
	data := map[string]interface{}{
		"value": base64.StdEncoding.EncodeToString([]byte(kubeconfig)),
	}
	got := caFromKubeconfigSecret(data, "value")
	if got != "QkFTRTY0Q0E=" {
		t.Fatalf("got %q, want QkFTRTY0Q0E=", got)
	}
}

func TestCAFromKubeconfigSecret_Missing(t *testing.T) {
	if got := caFromKubeconfigSecret(map[string]interface{}{}, "value"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
	// Not base64.
	if got := caFromKubeconfigSecret(map[string]interface{}{"value": "!!!notb64"}, "value"); got != "" {
		t.Fatalf("expected empty for bad base64, got %q", got)
	}
}

func TestCAFromKubeconfigSecret_KamajiAdminKey(t *testing.T) {
	kubeconfig := `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: S0FNQUpJQ0E=
    server: https://1.2.3.4:6443
  name: tenant
`
	data := map[string]interface{}{
		"super-admin.conf": base64.StdEncoding.EncodeToString([]byte(kubeconfig)),
	}
	got := caFromKubeconfigSecret(data, "super-admin.conf", "admin.conf", "value")
	if got != "S0FNQUpJQ0E=" {
		t.Fatalf("got %q, want S0FNQUpJQ0E=", got)
	}
}

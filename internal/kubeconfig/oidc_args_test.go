package kubeconfig

import "testing"

func TestApplyAPIServerOIDCArgs_KamajiStringList(t *testing.T) {
	// Kamaji shape: spec.apiServer.extraArgs as a list of "--flag=val" strings.
	spec := map[string]interface{}{
		"apiServer": map[string]interface{}{
			"extraArgs": []interface{}{
				"--oidc-issuer-url=https://issuer.example.com",
				"--oidc-client-id=my-client",
				"--oidc-client-secret=shh",
			},
		},
	}

	oidc := &OIDCConfig{}
	applyAPIServerOIDCArgs(spec, oidc)

	if oidc.IssuerURL != "https://issuer.example.com" {
		t.Errorf("issuer: got %q", oidc.IssuerURL)
	}
	if oidc.ClientID != "my-client" {
		t.Errorf("clientID: got %q", oidc.ClientID)
	}
	if oidc.ClientSecret != "shh" {
		t.Errorf("clientSecret: got %q", oidc.ClientSecret)
	}
}

func TestApplyAPIServerOIDCArgs_KubeadmNestedObjectList(t *testing.T) {
	// Kubeadm v1beta2 shape: nested under kubeadmConfigSpec.clusterConfiguration,
	// with extraArgs as a list of {name,value} objects.
	spec := map[string]interface{}{
		"kubeadmConfigSpec": map[string]interface{}{
			"clusterConfiguration": map[string]interface{}{
				"apiServer": map[string]interface{}{
					"extraArgs": []interface{}{
						map[string]interface{}{"name": "oidc-issuer-url", "value": "https://kubeadm.example.com"},
						map[string]interface{}{"name": "oidc-client-id", "value": "kubeadm-client"},
					},
				},
			},
		},
	}

	oidc := &OIDCConfig{}
	applyAPIServerOIDCArgs(spec, oidc)

	if oidc.IssuerURL != "https://kubeadm.example.com" {
		t.Errorf("issuer: got %q", oidc.IssuerURL)
	}
	if oidc.ClientID != "kubeadm-client" {
		t.Errorf("clientID: got %q", oidc.ClientID)
	}
}

func TestApplyAPIServerOIDCArgs_MapEncoding(t *testing.T) {
	// extraArgs as map[flag]val.
	spec := map[string]interface{}{
		"apiServer": map[string]interface{}{
			"extraArgs": map[string]interface{}{
				"oidc-issuer-url": "https://map.example.com",
				"oidc-client-id":  "map-client",
			},
		},
	}

	oidc := &OIDCConfig{}
	applyAPIServerOIDCArgs(spec, oidc)

	if oidc.IssuerURL != "https://map.example.com" {
		t.Errorf("issuer: got %q", oidc.IssuerURL)
	}
	if oidc.ClientID != "map-client" {
		t.Errorf("clientID: got %q", oidc.ClientID)
	}
}

func TestApplyAPIServerOIDCArgs_DoubleDashObjectName(t *testing.T) {
	// {name,value} objects where name includes the "--" prefix.
	spec := map[string]interface{}{
		"apiServer": map[string]interface{}{
			"extraArgs": []interface{}{
				map[string]interface{}{"name": "--oidc-issuer-url", "value": "https://dd.example.com"},
				map[string]interface{}{"name": "--oidc-client-id", "value": "dd-client"},
			},
		},
	}

	oidc := &OIDCConfig{}
	applyAPIServerOIDCArgs(spec, oidc)

	if oidc.IssuerURL != "https://dd.example.com" {
		t.Errorf("issuer: got %q", oidc.IssuerURL)
	}
	if oidc.ClientID != "dd-client" {
		t.Errorf("clientID: got %q", oidc.ClientID)
	}
}

func TestApplyAPIServerOIDCArgs_PrecedencePreserved(t *testing.T) {
	// Pre-set fields must not be overwritten (earlier paths take precedence).
	spec := map[string]interface{}{
		"apiServer": map[string]interface{}{
			"extraArgs": []interface{}{
				"--oidc-issuer-url=https://override.example.com",
			},
		},
	}

	oidc := &OIDCConfig{IssuerURL: "https://original.example.com"}
	applyAPIServerOIDCArgs(spec, oidc)

	if oidc.IssuerURL != "https://original.example.com" {
		t.Errorf("expected original issuer preserved, got %q", oidc.IssuerURL)
	}
}

func TestApplyAPIServerOIDCArgs_NoOIDCArgs(t *testing.T) {
	spec := map[string]interface{}{
		"apiServer": map[string]interface{}{
			"extraArgs": []interface{}{
				"--audit-log-path=/var/log/audit.log",
			},
		},
	}

	oidc := &OIDCConfig{}
	applyAPIServerOIDCArgs(spec, oidc)

	if oidc.IssuerURL != "" || oidc.ClientID != "" || oidc.ClientSecret != "" {
		t.Errorf("expected no OIDC config, got %+v", oidc)
	}
}

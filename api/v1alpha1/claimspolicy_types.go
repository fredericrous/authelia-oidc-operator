package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClaimsPolicySpec defines a claims policy for Authelia OIDC
type ClaimsPolicySpec struct {
	// PolicyName is the name referenced by OIDCClient.claimsPolicy
	// If not specified, derived from metadata.name (hyphens → underscores)
	// +optional
	PolicyName string `json:"policyName,omitempty"`

	// IDToken lists claims to include in ID tokens
	// +optional
	IDToken []string `json:"idToken,omitempty"`

	// Userinfo lists claims to include in userinfo responses
	// +optional
	Userinfo []string `json:"userinfo,omitempty"`

	// AccessToken lists claims to include in access tokens
	// +optional
	AccessToken []string `json:"accessToken,omitempty"`

	// Introspection lists claims to include in introspection responses
	// +optional
	Introspection []string `json:"introspection,omitempty"`

	// CustomClaims lists UserAttribute names to include as custom claims
	// Each must exist as a UserAttribute in the SAME namespace
	// +optional
	CustomClaims []string `json:"customClaims,omitempty"`

	// CustomScope defines a custom OIDC scope associated with this policy
	// +optional
	CustomScope *CustomScopeSpec `json:"customScope,omitempty"`
}

// CustomScopeSpec defines a custom OIDC scope
type CustomScopeSpec struct {
	// ScopeName is the scope name. Defaults to policy name if not set.
	// +optional
	ScopeName string `json:"scopeName,omitempty"`

	// Claims to include when this scope is requested
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Claims []string `json:"claims"`
}

// ClaimsPolicyStatus defines the observed state
type ClaimsPolicyStatus struct {
	// Ready indicates if the policy is valid and synced
	Ready bool `json:"ready,omitempty"`

	// ResolvedName is the final Authelia policy name
	ResolvedName string `json:"resolvedName,omitempty"`

	// LastSyncedAt is the timestamp of the last successful sync
	LastSyncedAt *metav1.Time `json:"lastSyncedAt,omitempty"`

	// Conditions represent the current state
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=cpol
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.status.resolvedName`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ClaimsPolicy is the Schema for the claimspolicies API
type ClaimsPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClaimsPolicySpec   `json:"spec,omitempty"`
	Status ClaimsPolicyStatus `json:"status,omitempty"`
}

// GetResolvedName returns the Authelia policy name
// Uses spec.policyName if set, otherwise converts metadata.name (hyphens → underscores)
func (c *ClaimsPolicy) GetResolvedName() string {
	if c.Spec.PolicyName != "" {
		return c.Spec.PolicyName
	}
	return hyphenToUnderscore(c.Name)
}

// GetScopeName returns the custom scope name if defined
// Uses customScope.scopeName if set, otherwise uses the resolved policy name
func (c *ClaimsPolicy) GetScopeName() string {
	if c.Spec.CustomScope == nil {
		return ""
	}
	if c.Spec.CustomScope.ScopeName != "" {
		return c.Spec.CustomScope.ScopeName
	}
	return c.GetResolvedName()
}

// +kubebuilder:object:root=true

// ClaimsPolicyList contains a list of ClaimsPolicy
type ClaimsPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClaimsPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClaimsPolicy{}, &ClaimsPolicyList{})
}

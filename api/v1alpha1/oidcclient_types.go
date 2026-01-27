package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OIDCClientSpec defines the desired state of OIDCClient
type OIDCClientSpec struct {
	// ClientID is the unique identifier for the OIDC client
	// +kubebuilder:validation:Required
	ClientID string `json:"clientId"`

	// ClientName is the display name for the client
	// +optional
	ClientName string `json:"clientName,omitempty"`

	// RedirectURIs are the allowed redirect URIs
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	RedirectURIs []string `json:"redirectUris"`

	// Scopes are the allowed scopes
	// +optional
	// +kubebuilder:default={"openid","profile","email","groups"}
	Scopes []string `json:"scopes,omitempty"`

	// ResponseTypes are the allowed response types
	// +optional
	// +kubebuilder:default={"code"}
	ResponseTypes []string `json:"responseTypes,omitempty"`

	// GrantTypes are the allowed grant types
	// +optional
	// +kubebuilder:default={"authorization_code"}
	GrantTypes []string `json:"grantTypes,omitempty"`

	// ResponseModes are the allowed response modes
	// +optional
	// +kubebuilder:default={"form_post","query","fragment"}
	ResponseModes []string `json:"responseModes,omitempty"`

	// UserinfoSignedResponseAlg is the algorithm for signing userinfo responses
	// +optional
	// +kubebuilder:default="none"
	UserinfoSignedResponseAlg string `json:"userinfoSignedResponseAlg,omitempty"`

	// TokenEndpointAuthMethod is the authentication method for the token endpoint
	// +optional
	// +kubebuilder:default="client_secret_basic"
	// +kubebuilder:validation:Enum=client_secret_basic;client_secret_post;none
	TokenEndpointAuthMethod string `json:"tokenEndpointAuthMethod,omitempty"`

	// RequirePKCE indicates if PKCE is required for authorization code flow
	// +optional
	// +kubebuilder:default=false
	RequirePKCE bool `json:"requirePkce,omitempty"`

	// PKCEChallengeMethod is the PKCE challenge method
	// +optional
	// +kubebuilder:default="S256"
	// +kubebuilder:validation:Enum=S256;plain
	PKCEChallengeMethod string `json:"pkceChallengeMethod,omitempty"`

	// SecretRef references an existing secret containing the client secret
	// +optional
	SecretRef *SecretReference `json:"secretRef,omitempty"`

	// GenerateSecret indicates if a secret should be generated
	// +optional
	// +kubebuilder:default=true
	GenerateSecret bool `json:"generateSecret,omitempty"`
}

// SecretReference references a secret in a namespace
type SecretReference struct {
	// Name of the secret
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the secret (defaults to the OIDCClient namespace)
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Key in the secret containing the client secret
	// +optional
	// +kubebuilder:default="client_secret"
	Key string `json:"key,omitempty"`
}

// OIDCClientStatus defines the observed state of OIDCClient
type OIDCClientStatus struct {
	// Ready indicates if the client is ready
	Ready bool `json:"ready,omitempty"`

	// SecretName is the name of the generated/referenced secret
	SecretName string `json:"secretName,omitempty"`

	// LastSyncedAt is the timestamp of the last successful sync
	LastSyncedAt *metav1.Time `json:"lastSyncedAt,omitempty"`

	// Conditions represent the current state of the OIDCClient
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=oidc
// +kubebuilder:printcolumn:name="Client ID",type=string,JSONPath=`.spec.clientId`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OIDCClient is the Schema for the oidcclients API
type OIDCClient struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OIDCClientSpec   `json:"spec,omitempty"`
	Status OIDCClientStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OIDCClientList contains a list of OIDCClient
type OIDCClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OIDCClient `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OIDCClient{}, &OIDCClientList{})
}

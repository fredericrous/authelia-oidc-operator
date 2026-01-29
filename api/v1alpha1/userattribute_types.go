package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// UserAttributeSpec defines a user attribute for Authelia
type UserAttributeSpec struct {
	// AttributeName is the name in Authelia config (snake_case)
	// If not specified, derived from metadata.name (hyphens → underscores)
	// +optional
	AttributeName string `json:"attributeName,omitempty"`

	// Expression is a CEL expression evaluated for each user
	// Context available: groups ([]string), username, email, display_name
	// Example: '"admin" in groups'
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Expression string `json:"expression"`
}

// UserAttributeStatus defines the observed state
type UserAttributeStatus struct {
	// Ready indicates if the attribute is valid and synced
	Ready bool `json:"ready,omitempty"`

	// ResolvedName is the final Authelia attribute name
	ResolvedName string `json:"resolvedName,omitempty"`

	// LastSyncedAt is the timestamp of the last successful sync
	LastSyncedAt *metav1.Time `json:"lastSyncedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=uattr
// +kubebuilder:printcolumn:name="Attribute",type=string,JSONPath=`.status.resolvedName`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// UserAttribute is the Schema for the userattributes API
type UserAttribute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UserAttributeSpec   `json:"spec,omitempty"`
	Status UserAttributeStatus `json:"status,omitempty"`
}

// GetResolvedName returns the Authelia attribute name
// Uses spec.attributeName if set, otherwise converts metadata.name (hyphens → underscores)
func (u *UserAttribute) GetResolvedName() string {
	if u.Spec.AttributeName != "" {
		return u.Spec.AttributeName
	}
	return hyphenToUnderscore(u.Name)
}

// +kubebuilder:object:root=true

// UserAttributeList contains a list of UserAttribute
type UserAttributeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UserAttribute `json:"items"`
}

func init() {
	SchemeBuilder.Register(&UserAttribute{}, &UserAttributeList{})
}

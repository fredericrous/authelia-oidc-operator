package controllers

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/fredericrous/homelab/authelia-oidc-operator/api/v1alpha1"
)

func statusScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := securityv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add to scheme: %v", err)
	}
	return s
}

func newClient(name string) *securityv1alpha1.OIDCClient {
	return &securityv1alpha1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "authelia"},
		Spec:       securityv1alpha1.OIDCClientSpec{ClientID: name},
		Status:     securityv1alpha1.OIDCClientStatus{Ready: true},
	}
}

// A client whose secret went missing must actually end up Ready=false. The old
// code logged the conflict and moved on, so this write was the one that could
// silently lose — leaving a broken client advertising Ready=true.
func TestUpdateClientStatusWritesReadyFalse(t *testing.T) {
	s := statusScheme(t)
	oc := newClient("kb-vision")
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(oc).
		WithStatusSubresource(&securityv1alpha1.OIDCClient{}).Build()
	r := &OIDCClientReconciler{Client: c, Log: logr.Discard()}

	key := types.NamespacedName{Name: "kb-vision", Namespace: "authelia"}
	if err := r.updateClientStatus(context.Background(), key, false); err != nil {
		t.Fatalf("updateClientStatus: %v", err)
	}

	got := &securityv1alpha1.OIDCClient{}
	if err := c.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.Ready {
		t.Error("Ready should be false")
	}
	if got.Status.LastSyncedAt == nil {
		t.Error("LastSyncedAt should be stamped")
	}
}

func TestUpdateClientStatusWritesReadyTrue(t *testing.T) {
	s := statusScheme(t)
	oc := newClient("gitea")
	oc.Status.Ready = false
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(oc).
		WithStatusSubresource(&securityv1alpha1.OIDCClient{}).Build()
	r := &OIDCClientReconciler{Client: c, Log: logr.Discard()}

	key := types.NamespacedName{Name: "gitea", Namespace: "authelia"}
	if err := r.updateClientStatus(context.Background(), key, true); err != nil {
		t.Fatalf("updateClientStatus: %v", err)
	}

	got := &securityv1alpha1.OIDCClient{}
	if err := c.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Status.Ready {
		t.Error("Ready should be true")
	}
}

// A client deleted between the list and the status write is not a failure —
// there is simply nothing left to publish. Returning an error here would log
// noise indistinguishable from the conflicts this change exists to remove.
func TestUpdateClientStatusIgnoresDeletedClient(t *testing.T) {
	s := statusScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).
		WithStatusSubresource(&securityv1alpha1.OIDCClient{}).Build()
	r := &OIDCClientReconciler{Client: c, Log: logr.Discard()}

	key := types.NamespacedName{Name: "gone", Namespace: "authelia"}
	if err := r.updateClientStatus(context.Background(), key, true); err != nil {
		t.Errorf("a deleted client should not be an error, got %v", err)
	}
}

// The write must go through a FRESH read, not the caller's copy. That is what
// makes RetryOnConflict able to succeed: retrying with the same stale
// resourceVersion would conflict forever.
func TestUpdateClientStatusRereadsBeforeWriting(t *testing.T) {
	s := statusScheme(t)
	oc := newClient("n8n")
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(oc).
		WithStatusSubresource(&securityv1alpha1.OIDCClient{}).Build()
	r := &OIDCClientReconciler{Client: c, Log: logr.Discard()}

	key := types.NamespacedName{Name: "n8n", Namespace: "authelia"}

	// Mutate the stored object behind the caller's back, the way another writer
	// would. A write built on the caller's now-stale copy would clobber this.
	stored := &securityv1alpha1.OIDCClient{}
	if err := c.Get(context.Background(), key, stored); err != nil {
		t.Fatalf("get: %v", err)
	}
	stored.Labels = map[string]string{"touched": "yes"}
	if err := c.Update(context.Background(), stored); err != nil {
		t.Fatalf("update: %v", err)
	}

	if err := r.updateClientStatus(context.Background(), key, false); err != nil {
		t.Fatalf("updateClientStatus: %v", err)
	}

	got := &securityv1alpha1.OIDCClient{}
	if err := c.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Labels["touched"] != "yes" {
		t.Error("the concurrent label write was lost — status update did not re-read")
	}
	if got.Status.Ready {
		t.Error("Ready should be false")
	}
}

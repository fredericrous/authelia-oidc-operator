package controllers

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/fredericrous/homelab/authelia-oidc-operator/api/v1alpha1"
)

var _ = Describe("OIDCClient Controller Integration", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When creating an OIDCClient", func() {
		It("Should create the client and update status", func() {
			By("Creating a new OIDCClient")
			oidcClient := &securityv1alpha1.OIDCClient{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "security.homelab.io/v1alpha1",
					Kind:       "OIDCClient",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-client",
					Namespace: "authelia",
				},
				Spec: securityv1alpha1.OIDCClientSpec{
					ClientID:     "test-client-id",
					ClientName:   "Test Client",
					RedirectURIs: []string{"https://app.example.com/callback"},
				},
			}
			Expect(k8sClient.Create(ctx, oidcClient)).Should(Succeed())

			By("Checking the OIDCClient was created")
			createdClient := &securityv1alpha1.OIDCClient{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-client",
					Namespace: "authelia",
				}, createdClient)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			Expect(createdClient.Spec.ClientID).Should(Equal("test-client-id"))
			Expect(createdClient.Spec.RedirectURIs).Should(ContainElement("https://app.example.com/callback"))

			By("Checking the status is eventually updated")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-client",
					Namespace: "authelia",
				}, createdClient)
				if err != nil {
					return false
				}
				return createdClient.Status.Ready
			}, timeout, interval).Should(BeTrue())
		})

		It("Should handle client with secret reference", func() {
			By("Creating a secret for the client")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-client-secret",
					Namespace: "authelia",
				},
				StringData: map[string]string{
					"client_secret": "super-secret-value",
				},
			}
			Expect(k8sClient.Create(ctx, secret)).Should(Succeed())

			By("Creating an OIDCClient with secret reference")
			oidcClient := &securityv1alpha1.OIDCClient{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "security.homelab.io/v1alpha1",
					Kind:       "OIDCClient",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client-with-secret",
					Namespace: "authelia",
				},
				Spec: securityv1alpha1.OIDCClientSpec{
					ClientID:     "client-with-secret-id",
					ClientName:   "Client With Secret",
					RedirectURIs: []string{"https://app2.example.com/callback"},
					SecretRef: &securityv1alpha1.SecretReference{
						Name: "my-client-secret",
					},
				},
			}
			Expect(k8sClient.Create(ctx, oidcClient)).Should(Succeed())

			By("Checking the OIDCClient status is Ready")
			createdClient := &securityv1alpha1.OIDCClient{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "client-with-secret",
					Namespace: "authelia",
				}, createdClient)
				if err != nil {
					return false
				}
				return createdClient.Status.Ready
			}, timeout, interval).Should(BeTrue())
		})

		It("Should handle public clients without secrets", func() {
			By("Creating a public OIDCClient")
			oidcClient := &securityv1alpha1.OIDCClient{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "security.homelab.io/v1alpha1",
					Kind:       "OIDCClient",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "public-client",
					Namespace: "authelia",
				},
				Spec: securityv1alpha1.OIDCClientSpec{
					ClientID:     "public-client-id",
					ClientName:   "Public Client",
					Public:       true,
					RedirectURIs: []string{"https://spa.example.com/callback"},
				},
			}
			Expect(k8sClient.Create(ctx, oidcClient)).Should(Succeed())

			By("Checking the public client is Ready")
			createdClient := &securityv1alpha1.OIDCClient{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "public-client",
					Namespace: "authelia",
				}, createdClient)
				if err != nil {
					return false
				}
				return createdClient.Status.Ready
			}, timeout, interval).Should(BeTrue())

			Expect(createdClient.Spec.Public).Should(BeTrue())
		})
	})

	Context("When updating an OIDCClient", func() {
		It("Should reconcile on updates", func() {
			By("Creating an OIDCClient")
			oidcClient := &securityv1alpha1.OIDCClient{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "security.homelab.io/v1alpha1",
					Kind:       "OIDCClient",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "update-test-client",
					Namespace: "authelia",
				},
				Spec: securityv1alpha1.OIDCClientSpec{
					ClientID:     "update-test-id",
					ClientName:   "Update Test Client",
					RedirectURIs: []string{"https://app3.example.com/callback"},
				},
			}
			Expect(k8sClient.Create(ctx, oidcClient)).Should(Succeed())

			By("Waiting for Ready status")
			createdClient := &securityv1alpha1.OIDCClient{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "update-test-client",
					Namespace: "authelia",
				}, createdClient)
				if err != nil {
					return false
				}
				return createdClient.Status.Ready
			}, timeout, interval).Should(BeTrue())

			By("Updating the redirect URIs")
			createdClient.Spec.RedirectURIs = append(createdClient.Spec.RedirectURIs, "https://app3-new.example.com/callback")
			Expect(k8sClient.Update(ctx, createdClient)).Should(Succeed())

			By("Verifying the update was applied")
			updatedClient := &securityv1alpha1.OIDCClient{}
			Eventually(func() int {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "update-test-client",
					Namespace: "authelia",
				}, updatedClient)
				if err != nil {
					return 0
				}
				return len(updatedClient.Spec.RedirectURIs)
			}, timeout, interval).Should(Equal(2))
		})
	})
})

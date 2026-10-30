package controllers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	securityv1alpha1 "github.com/fredericrous/homelab/authelia-oidc-operator/api/v1alpha1"
)

var (
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
	ctx       context.Context
	cancel    context.CancelFunc
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

// envtestAssetsPresent reports whether KUBEBUILDER_ASSETS points at a
// directory that actually holds a control plane. `make test` sets it; a bare
// `go test ./...` (the amont push gate) does not, and `make test-unit` (CI)
// leaves this package out.
func envtestAssetsPresent() bool {
	dir := os.Getenv("KUBEBUILDER_ASSETS")
	if dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, "etcd"))
	return err == nil
}

var _ = BeforeSuite(func() {
	if !envtestAssetsPresent() {
		Skip("KUBEBUILDER_ASSETS is unset or has no etcd; run `make test` for the controller suite")
	}
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = securityv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	// Create the authelia namespace for tests
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "authelia",
		},
	}
	err = k8sClient.Create(ctx, ns)
	Expect(err).NotTo(HaveOccurred())

	// Create base ConfigMap for Authelia
	baseCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "authelia-config-base",
			Namespace: "authelia",
		},
		Data: map[string]string{
			"configuration.yml": "server:\n  host: 0.0.0.0\n  port: 9091\n",
		},
	}
	err = k8sClient.Create(ctx, baseCM)
	Expect(err).NotTo(HaveOccurred())

	// Start controller manager
	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	err = (&OIDCClientReconciler{
		Client:   k8sManager.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("OIDCClient"),
		Scheme:   k8sManager.GetScheme(),
		Recorder: k8sManager.GetEventRecorderFor("oidcclient-controller"),
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred())
	}()
})

var _ = AfterSuite(func() {
	if testEnv == nil {
		return
	}
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

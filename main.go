package main

import (
	"flag"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	securityv1alpha1 "github.com/fredericrous/homelab/authelia-oidc-operator/api/v1alpha1"
	"github.com/fredericrous/homelab/authelia-oidc-operator/controllers"
	"github.com/fredericrous/homelab/authelia-oidc-operator/pkg/config"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          = flag.String("metrics-bind-address", ":8080", "The address the metric endpoint binds to")
		probeAddr            = flag.String("health-probe-bind-address", ":8081", "The address the probe endpoint binds to")
		enableLeaderElection = flag.Bool("leader-elect", false, "Enable leader election for controller manager")
		leaderElectionID     = flag.String("leader-election-id", "authelia-oidc-operator", "Leader election ID")

		maxConcurrentReconciles = flag.Int("max-concurrent-reconciles", 3, "Maximum number of concurrent reconciles")
		reconcileTimeout        = flag.Duration("reconcile-timeout", 5*time.Minute, "Timeout for each reconcile operation")

		autheliaNamespace         = flag.String("authelia-namespace", "authelia", "Namespace where Authelia is deployed")
		autheliaConfigMapName     = flag.String("authelia-configmap", "authelia-config", "Name of the Authelia ConfigMap")
		autheliaConfigMapBaseName = flag.String("authelia-configmap-base", "authelia-config-base", "Name of the base Authelia ConfigMap")
		oidcSecretsName           = flag.String("oidc-secrets", "authelia-oidc-secrets", "Name of the OIDC secrets secret")

		logLevel   = flag.String("zap-log-level", "info", "Zap log level (debug, info, warn, error)")
		logDevel   = flag.Bool("zap-devel", false, "Enable development mode logging")
		logEncoder = flag.String("zap-encoder", "json", "Zap log encoding (json or console)")
	)

	flag.Parse()

	// Setup logging
	opts := zap.Options{
		Development: *logDevel,
		TimeEncoder: zapcore.ISO8601TimeEncoder,
	}

	switch *logLevel {
	case "debug":
		opts.Level = zapcore.DebugLevel
	case "info":
		opts.Level = zapcore.InfoLevel
	case "warn":
		opts.Level = zapcore.WarnLevel
	case "error":
		opts.Level = zapcore.ErrorLevel
	default:
		opts.Level = zapcore.InfoLevel
	}

	if *logEncoder == "console" {
		opts.Encoder = zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		})
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Create configuration
	cfg := &config.OperatorConfig{
		MetricsAddr:               *metricsAddr,
		ProbeAddr:                 *probeAddr,
		EnableLeaderElection:      *enableLeaderElection,
		LeaderElectionID:          *leaderElectionID,
		MaxConcurrentReconciles:   *maxConcurrentReconciles,
		ReconcileTimeout:          *reconcileTimeout,
		AutheliaNamespace:         *autheliaNamespace,
		AutheliaConfigMapName:     *autheliaConfigMapName,
		AutheliaConfigMapBaseName: *autheliaConfigMapBaseName,
		OIDCSecretsName:           *oidcSecretsName,
	}

	if err := cfg.Validate(); err != nil {
		setupLog.Error(err, "Invalid configuration")
		os.Exit(1)
	}

	setupLog.Info("Starting authelia-oidc-operator",
		"autheliaNamespace", cfg.AutheliaNamespace,
		"metricsAddr", cfg.MetricsAddr,
		"probeAddr", cfg.ProbeAddr,
		"enableLeaderElection", cfg.EnableLeaderElection,
		"maxConcurrentReconciles", cfg.MaxConcurrentReconciles,
	)

	// Create manager
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: cfg.ProbeAddr,
		LeaderElection:         cfg.EnableLeaderElection,
		LeaderElectionID:       cfg.LeaderElectionID,
	})
	if err != nil {
		setupLog.Error(err, "Failed to create manager")
		os.Exit(1)
	}

	// Create the recorder for events
	recorder := mgr.GetEventRecorderFor("authelia-oidc-operator")

	// Setup controller
	reconciler := &controllers.OIDCClientReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("OIDCClient"),
		Scheme:   mgr.GetScheme(),
		Recorder: recorder,
		Config:   cfg,
	}

	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to setup controller")
		os.Exit(1)
	}

	// Add health checks
	if err := mgr.AddHealthzCheck("healthz", func(req *http.Request) error {
		return nil
	}); err != nil {
		setupLog.Error(err, "Failed to add health check")
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("readyz", func(req *http.Request) error {
		return nil
	}); err != nil {
		setupLog.Error(err, "Failed to add readiness check")
		os.Exit(1)
	}

	// Start the manager
	setupLog.Info("Starting manager")
	ctx := ctrl.SetupSignalHandler()
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}

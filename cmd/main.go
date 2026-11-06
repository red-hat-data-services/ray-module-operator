/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	tlspkg "github.com/opendatahub-io/odh-platform-utilities/framework/tls"
	configv1 "github.com/openshift/api/config/v1"
	commonTLS "github.com/openshift/controller-runtime-common/pkg/tls"

	componentsv1alpha1 "github.com/opendatahub-io/ray-module-operator/api/v1alpha1"
	"github.com/opendatahub-io/ray-module-operator/internal/constants"
	"github.com/opendatahub-io/ray-module-operator/internal/controller"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
	utilruntime.Must(configv1.AddToScheme(scheme)) // APIServer cluster TLS profile

	utilruntime.Must(componentsv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

type managerConfig struct {
	metricsAddr          string
	probeAddr            string
	enableLeaderElection bool
	secureMetrics        bool
	enableHTTP2          bool
	metricsCertPath      string
	metricsCertName      string
	metricsCertKey       string
	webhookCertPath      string
	webhookCertName      string
	webhookCertKey       string
}

func parseFlags() managerConfig {
	cfg := managerConfig{}
	flag.StringVar(&cfg.metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&cfg.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&cfg.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&cfg.secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&cfg.webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&cfg.webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&cfg.webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&cfg.metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&cfg.metricsCertName, "metrics-cert-name", "tls.crt",
		"The name of the metrics server certificate file.")
	flag.StringVar(&cfg.metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&cfg.enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	return cfg
}

// managerTLSOptions resolves the OpenShift APIServer TLS security profile and
// adherence policy and returns the TLS options for the metrics and webhook
// servers, plus the load result used to register the profile watcher.
//
// +kubebuilder:rbac:groups=config.openshift.io,resources=apiservers,verbs=get;list;watch
func managerTLSOptions(
	ctx context.Context,
	cli client.Reader,
	enableHTTP2 bool,
) ([]func(*tls.Config), tlspkg.LoadResult, error) {
	result, err := tlspkg.LoadWithAdherence(ctx, cli)
	if err != nil {
		// Fail closed: refuse to start when the TLS posture cannot be determined.
		return nil, result, fmt.Errorf("unable to load APIServer TLS profile: %w", err)
	}

	if result.UsedFallback {
		if result.Watchable {
			setupLog.Info("transient API error loading TLS settings; " +
				"using Intermediate defaults and waiting for watcher recovery")
		} else {
			setupLog.Info("APIServer TLS API unavailable; using Intermediate defaults")
		}
	}

	profile := result.Spec
	if !tlspkg.ShouldHonorClusterTLSProfile(result.AdherencePolicy) {
		// Non-adhering policy: use hardened Intermediate defaults (TLS 1.2 + ECDHE AEAD).
		profile = *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	}

	tlsConfigFn, unsupported, err := tlspkg.ConfigFromProfileWithError(profile)
	if err != nil {
		return nil, result, fmt.Errorf("building TLS options from profile: %w", err)
	}
	if len(unsupported) > 0 {
		setupLog.Info("some TLS settings from profile are not supported by Go", "unsupported", unsupported)
	}

	// Keep the legacy --enable-http2=false semantics: HTTP/2 stays disabled by
	// default (rapid reset CVEs), overriding the profile's ALPN.
	nextProtos := commonTLS.SetNextProtos(commonTLS.HTTP2NextProtos...)
	if !enableHTTP2 {
		setupLog.Info("Disabling HTTP/2")
		nextProtos = commonTLS.SetNextProtos(commonTLS.HTTP1NextProtos...)
	}

	return []func(*tls.Config){tlsConfigFn, nextProtos}, result, nil
}

// registerTLSProfileWatcher cancels the returned context when the cluster TLS
// profile or adherence policy changes, so the pod restarts with fresh settings.
func registerTLSProfileWatcher(ctx context.Context, mgr ctrl.Manager, load tlspkg.LoadResult) context.Context {
	watcherCtx, cancel := context.WithCancel(ctx)

	watcher := newTLSProfileWatcher(mgr.GetClient(), load, cancel)
	if err := watcher.SetupWithManager(mgr); err != nil {
		cancel()
		setupLog.Error(err, "Failed to register TLS security profile watcher")
		os.Exit(1)
	}

	return watcherCtx
}

// newTLSProfileWatcher builds the profile/adherence watcher seeded with the
// bootstrap result; any observed change triggers a graceful-shutdown reload.
func newTLSProfileWatcher(
	cli client.Client, load tlspkg.LoadResult, cancel context.CancelFunc,
) *tlspkg.SecurityProfileWatcher {
	return &tlspkg.SecurityProfileWatcher{
		Client:                    cli,
		InitialTLSProfileSpec:     load.Spec,
		InitialTLSAdherencePolicy: load.AdherencePolicy,
		OnProfileChange: func(_ context.Context, _, _ configv1.TLSProfileSpec) {
			setupLog.Info("TLS profile changed, initiating graceful shutdown to reload")
			cancel()
		},
		OnAdherencePolicyChange: func(_ context.Context, _, _ configv1.TLSAdherencePolicy) {
			setupLog.Info("TLS adherence policy changed, initiating graceful shutdown to reload")
			cancel()
		},
	}
}

func setupWebhookServer(cfg managerConfig, tlsOpts []func(*tls.Config)) webhook.Server {
	opts := webhook.Options{TLSOpts: tlsOpts}
	if len(cfg.webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", cfg.webhookCertPath, "webhook-cert-name", cfg.webhookCertName,
			"webhook-cert-key", cfg.webhookCertKey)
		opts.CertDir = cfg.webhookCertPath
		opts.CertName = cfg.webhookCertName
		opts.KeyName = cfg.webhookCertKey
	}
	return webhook.NewServer(opts)
}

func setupMetricsOptions(cfg managerConfig, tlsOpts []func(*tls.Config)) metricsserver.Options {
	opts := metricsserver.Options{
		BindAddress:   cfg.metricsAddr,
		SecureServing: cfg.secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if cfg.secureMetrics {
		opts.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	if len(cfg.metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", cfg.metricsCertPath, "metrics-cert-name", cfg.metricsCertName,
			"metrics-cert-key", cfg.metricsCertKey)
		opts.CertDir = cfg.metricsCertPath
		opts.CertName = cfg.metricsCertName
		opts.KeyName = cfg.metricsCertKey
	}
	return opts
}

func setupManager(cfg managerConfig, restCfg *rest.Config, tlsOpts []func(*tls.Config)) ctrl.Manager {
	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                setupMetricsOptions(cfg, tlsOpts),
		WebhookServer:          setupWebhookServer(cfg, tlsOpts),
		HealthProbeBindAddress: cfg.probeAddr,
		LeaderElection:         cfg.enableLeaderElection,
		LeaderElectionID:       "0dc2a3f5.platform.opendatahub.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}
	return mgr
}

func registerControllers(ctx context.Context, mgr ctrl.Manager) {
	if err := controller.SetupWithManager(ctx, mgr, constants.ManifestsBasePath); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "ray")
		os.Exit(1)
	}
}

func registerHealthChecks(mgr ctrl.Manager) {
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}
}

func main() {
	cfg := parseFlags()
	ctx := ctrl.SetupSignalHandler()

	restCfg := ctrl.GetConfigOrDie()
	// Bound every bootstrap request, including the REST mapper's discovery
	// calls, which the load context does not cover.
	bootstrapCfg := rest.CopyConfig(restCfg)
	bootstrapCfg.Timeout = 10 * time.Second
	bootstrapClient, err := client.New(bootstrapCfg, client.Options{Scheme: scheme})
	if err != nil {
		// Refuse to start: the TLS posture cannot be determined and the same
		// rest.Config would fail manager construction anyway.
		setupLog.Error(err, "Failed to create bootstrap client for TLS profile")
		os.Exit(1)
	}

	// Bound the bootstrap TLS read like the other TLS-family operators
	// (10s): a deadline is transient-classified, so a nonresponding API
	// server falls back to Intermediate with watcher recovery instead of
	// hanging startup before the manager's probes exist.
	loadCtx, loadCancel := context.WithTimeout(ctx, 10*time.Second)
	tlsOpts, tlsLoad, err := managerTLSOptions(loadCtx, bootstrapClient, cfg.enableHTTP2)
	loadCancel()
	if err != nil {
		setupLog.Error(err, "Failed to establish manager TLS configuration")
		os.Exit(1)
	}

	mgr := setupManager(cfg, restCfg, tlsOpts)
	registerControllers(ctx, mgr)
	registerHealthChecks(mgr)

	if tlsLoad.Watchable {
		ctx = registerTLSProfileWatcher(ctx, mgr, tlsLoad)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}

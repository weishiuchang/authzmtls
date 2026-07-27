package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	_ "go.uber.org/automaxprocs" // sets GOMAXPROCS from the container's CPU quota via its init() side effect

	"github.com/weishiuchang/authzmtls/internal/config"
	"github.com/weishiuchang/authzmtls/internal/datasources"
	_ "github.com/weishiuchang/authzmtls/internal/datasources/ldap" // registers the "ldap" datasource type via its init()
	"github.com/weishiuchang/authzmtls/internal/logging"
	"github.com/weishiuchang/authzmtls/internal/rules"
	"github.com/weishiuchang/authzmtls/internal/server"
	"github.com/weishiuchang/authzmtls/internal/telemetry"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// shutdownGracePeriod bounds graceful shutdown after SIGINT/SIGTERM.
const shutdownGracePeriod = 30 * time.Second

// cli is authzmtls's command-line interface.
type cli struct {
	ConfigPath      string           `arg:"" name:"config-path" type:"existingfile" help:"Path to config.yaml."`
	LoggingLevel    string           `name:"logging-level" help:"Log level: trace, debug, info, warn, error (default: info)."`
	ListenAddr      string           `name:"listen-addr" help:"Address the HTTP server listens on (default: :80)."`
	ServerCert      string           `name:"server-cert" type:"path" help:"Path to TLS server certificate (optional; plain HTTP if unset)."`
	ServerKey       string           `name:"server-key" type:"path" help:"Path to TLS server private key (optional; plain HTTP if unset)."`
	MetricsPath     string           `name:"metrics-path" help:"Prometheus metrics endpoint path (default: /metrics)."`
	DecisionTimeout string           `name:"decision-timeout" help:"Timeout for a single datasource resolution call, e.g. 2s (default: 2s)."`
	Version         kong.VersionFlag `help:"Print version and exit."`
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		os.Exit(1)
	}
}

// SIGHUP reloads configs, rereads tls, and invalidates caches
func run(ctx context.Context, args []string) error {
	var c cli
	parser, err := kong.New(&c,
		kong.Name("authzmtls"),
		kong.Description("Docker authorization plugin"),
		kong.Vars{"version": version},
		kong.UsageOnError(),
	)
	if err != nil {
		return fmt.Errorf("build CLI parser: %w", err)
	}

	bootLogger := logging.New("info") // used until cfg.LoggingLevel is loaded
	if _, err := parser.Parse(args); err != nil {
		bootLogger.Error("startup: failed to parse arguments", "error", err.Error())
		return fmt.Errorf("parse arguments: %w", err)
	}

	overrides := config.FlagOverrides{
		LoggingLevel:    c.LoggingLevel,
		ListenAddr:      c.ListenAddr,
		ServerCert:      c.ServerCert,
		ServerKey:       c.ServerKey,
		MetricsPath:     c.MetricsPath,
		DecisionTimeout: c.DecisionTimeout,
	}

	cfg, err := config.LoadFull(c.ConfigPath, overrides)
	if err != nil {
		bootLogger.Error("startup: failed to load configuration", "config_path", c.ConfigPath, "error", err.Error())
		return fmt.Errorf("load configuration: %w", err)
	}

	logger := logging.New(cfg.LoggingLevel)
	slog.SetDefault(logger) // internal/config logs its own WARN/INFO lines through the package-level default

	logger.Debug("startup: allowlist", "allowlist", cfg.Allowlist)

	_ = telemetry.MeterProvider() // constructed explicitly here, in this file's dependency order, rather than as a side effect below

	dsSet, err := datasources.NewSet(convertDatasources(cfg.Datasources), logger)
	if err != nil {
		logger.Error("startup: failed to construct datasources", "error", err.Error())
		return fmt.Errorf("construct datasources: %w", err)
	}

	chain, err := rules.NewBuiltinChain(cfg, dsSet, logger)
	if err != nil {
		logger.Error("startup: failed to construct rule chain", "error", err.Error())
		return fmt.Errorf("construct rule chain: %w", err)
	}

	srv, err := server.New(cfg, chain, telemetry.Handler(), logger)
	if err != nil {
		logger.Error("startup: failed to construct server", "error", err.Error())
		return fmt.Errorf("construct server: %w", err)
	}

	logger.Info("STARTING", "version", version, "listen_addr", cfg.Server.ListenAddr, "config_path", c.ConfigPath)

	if _, err := srv.Start(); err != nil {
		logger.Error("startup: failed to start listening", "listen_addr", cfg.Server.ListenAddr, "error", err.Error())
		return fmt.Errorf("start server: %w", err)
	}

	store := config.NewStore(cfg)
	stopWatch := config.Watch(store, c.ConfigPath, overrides, func(newCfg *config.Config, reloadErr error) {
		if reloadErr != nil {
			// A bad reload is fatal, exactly like a bad config at startup.
			logger.Error("reload: failed to load configuration", "config_path", c.ConfigPath, "error", reloadErr.Error())
			os.Exit(1)
		}
		if err := srv.Reload(newCfg); err != nil {
			logger.Error("reload: failed to apply configuration", "config_path", c.ConfigPath, "error", err.Error())
			os.Exit(1)
		}
	})
	defer stopWatch()

	// signal.NotifyContext layers real SIGINT/SIGTERM under ctx's own
	// cancellation, so tests can trigger shutdown by canceling ctx directly.
	shutdownCtx, stopSignals := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	<-shutdownCtx.Done()

	logger.Info("SHUTTING DOWN")

	drainCtx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
	defer cancel()

	if err := srv.Shutdown(drainCtx); err != nil {
		logger.Warn("shutdown: server did not drain cleanly within the grace period", "error", err.Error())
	}
	if err := telemetry.Shutdown(drainCtx); err != nil {
		logger.Warn("shutdown: failed to flush telemetry", "error", err.Error())
	}

	return nil
}

// convertDatasources adapts internal/config's config-file datasource shape
// into internal/datasources' runtime shape.
func convertDatasources(cfgs []config.DatasourceConfig) []datasources.Config {
	out := make([]datasources.Config, len(cfgs))
	for i, c := range cfgs {
		out[i] = datasources.Config{
			Name:     c.Name,
			Type:     c.Type,
			CacheTTL: time.Duration(c.CacheTTL),
			Raw:      c.Raw,
		}
	}
	return out
}

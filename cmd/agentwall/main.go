package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/balyakin/agentwall/internal/budget"
	"github.com/balyakin/agentwall/internal/ca"
	"github.com/balyakin/agentwall/internal/config"
	"github.com/balyakin/agentwall/internal/doctor"
	auditlog "github.com/balyakin/agentwall/internal/log"
	"github.com/balyakin/agentwall/internal/proxy"
	"github.com/balyakin/agentwall/internal/replay"
	"github.com/balyakin/agentwall/internal/response"
	"github.com/balyakin/agentwall/internal/rules"
	"github.com/balyakin/agentwall/internal/sanitize"
	"github.com/balyakin/agentwall/internal/supervisor"
	"github.com/balyakin/agentwall/internal/ui"
	"github.com/balyakin/agentwall/internal/version"
)

type cliFlags struct {
	configPath         string
	mode               string
	port               int
	upstreamProxy      string
	budget             string
	responseSanitize   string
	codexPassthrough   bool
	noCodexPassthrough bool
	failOnBlocked      bool
	saveSession        string
	replay             string
	split              bool
	noColor            bool
	quiet              bool
	json               bool
	explain            bool
	noSanitize         bool
}

type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }

func main() {
	if err := newRootCmd().Execute(); err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			if ee.err != nil {
				_, _ = fmt.Fprintln(os.Stderr, ee.err)
			}
			os.Exit(ee.code)
		}
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	flags := &cliFlags{}
	root := &cobra.Command{
		Use:   "agentwall",
		Short: "A zero-config network firewall for AI coding agents",
	}

	root.PersistentFlags().StringVar(&flags.configPath, "config", "", "path to config file")
	root.PersistentFlags().StringVar(&flags.mode, "mode", "", "loose|balanced|strict")
	root.PersistentFlags().IntVar(&flags.port, "port", 0, "proxy port")
	root.PersistentFlags().StringVar(&flags.upstreamProxy, "upstream-proxy", "", "optional upstream proxy URL")
	root.PersistentFlags().StringVar(&flags.budget, "budget", "", "session budget (e.g. 5$, USD:5)")
	root.PersistentFlags().StringVar(&flags.responseSanitize, "response-sanitize", "", "off|detect|sanitize|block")
	root.PersistentFlags().BoolVar(&flags.codexPassthrough, "codex-passthrough", false, "compatibility mode for codex: passthrough chatgpt.com (disables body-level protection)")
	root.PersistentFlags().BoolVar(&flags.noCodexPassthrough, "no-codex-passthrough", false, "disable codex passthrough and force body inspection (may be slower/unstable)")
	root.PersistentFlags().BoolVar(&flags.failOnBlocked, "fail-on-blocked", false, "non-zero exit if anything was blocked")
	root.PersistentFlags().StringVar(&flags.saveSession, "save-session", "", "save normalized session trace")
	root.PersistentFlags().StringVar(&flags.replay, "replay", "", "replay session from file")
	root.PersistentFlags().BoolVar(&flags.split, "split", false, "interactive split TUI (MVP fallback: inline)")
	root.PersistentFlags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	root.PersistentFlags().BoolVar(&flags.quiet, "quiet", false, "suppress event log")
	root.PersistentFlags().BoolVar(&flags.json, "json", false, "emit JSON events to stderr")
	root.PersistentFlags().BoolVar(&flags.explain, "explain", false, "interactive request confirmation mode")
	root.PersistentFlags().BoolVar(&flags.noSanitize, "no-sanitize", false, "disable request+response redaction")

	root.AddCommand(newRunCmd(flags))
	root.AddCommand(newWatchCmd(flags))
	root.AddCommand(newReplayCmd(flags))
	root.AddCommand(newDoctorCmd(flags))
	root.AddCommand(newCACmd(flags))
	root.AddCommand(newRulesCmd(flags))
	root.AddCommand(newLogCmd(flags))
	root.AddCommand(newInitCmd(flags))
	root.AddCommand(newVersionCmd())

	return root
}

func newRunCmd(flags *cliFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:                "run -- <command> [args...]",
		Short:              "Runs child command behind AgentWall proxy",
		DisableFlagParsing: false,
		Args:               cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgentWall(flags, args)
		},
	}
	return cmd
}

func runAgentWall(flags *cliFlags, childCmd []string) error {
	if len(childCmd) == 0 {
		return errors.New("missing child command, use: agentwall run -- <command> [args...]")
	}
	if os.Getenv("AGENTWALL_DISABLE") == "1" {
		cmd := exec.Command(childCmd[0], childCmd[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				if status, ok := ee.Sys().(syscall.WaitStatus); ok {
					return exitError{code: status.ExitStatus(), err: fmt.Errorf("child exited with code %d", status.ExitStatus())}
				}
				return exitError{code: 1, err: err}
			}
			return err
		}
		return nil
	}

	cfg, err := config.Load(flags.configPath)
	if err != nil {
		return err
	}
	if err := applyFlagOverrides(&cfg, flags); err != nil {
		return err
	}
	if !cfg.Sanitizers.Enabled {
		_, _ = fmt.Fprintln(os.Stderr, "WARNING: sanitization is disabled (--no-sanitize / AGENTWALL_NO_SANITIZE=1). Secrets may leak.")
	}

	appDir, err := config.AppDir()
	if err != nil {
		return err
	}
	caManager := ca.New(appDir)
	if err := caManager.Ensure(); err != nil {
		return err
	}
	caCert, err := caManager.TLSCertificate()
	if err != nil {
		return err
	}

	logWriter, err := auditlog.NewWriter(cfg.Log.Path, cfg.Log.MaxSizeMB, cfg.Log.Rotate, cfg.Log.MaxBackups, cfg.Log.MaxAgeDays, cfg.Log.Compress)
	if err != nil {
		return err
	}
	defer logWriter.Close()

	sanitizer, err := sanitize.New(sanitize.Config{
		Enabled:      cfg.Sanitizers.Enabled,
		MaxBodyBytes: cfg.Sanitizers.MaxBodyKB * 1024,
		Custom:       convertCustomSanitizers(cfg.Sanitizers.Custom),
	})
	if err != nil {
		return err
	}
	if cfg.EnvGuard.Enabled {
		secrets, _ := sanitize.DiscoverEnvSecrets(".", cfg.EnvGuard.Discover, cfg.EnvGuard.MaxFileKB)
		sanitizer.SetEnvSecrets(secrets)
	}

	budgetAmount := cfg.Budget.USD
	if flags.budget != "" {
		parsed, err := budget.ParseBudget(flags.budget)
		if err != nil {
			return err
		}
		budgetAmount = parsed
	}
	budgetController := budget.New(budgetAmount, cfg.Budget.OnExceed)

	engine, err := rules.New(cfg.Mode, convertRuleConfigs(cfg.Rules))
	if err != nil {
		return err
	}

	liveEventsMuted := shouldMuteLiveEvents(flags, childCmd)
	inline := ui.NewInline(os.Stderr, flags.noColor, flags.json, flags.quiet)
	if liveEventsMuted {
		inline.SetEventsMuted(true)
	}
	if flags.split {
		_, _ = fmt.Fprintln(os.Stderr, "INFO: --split is not available in this build; falling back to inline mode.")
	}
	inline.Banner(version.String(), cfg.Mode, fmt.Sprintf("127.0.0.1:%d", cfg.Port), strings.Join(childCmd, " "))
	if liveEventsMuted && !flags.quiet {
		_, _ = fmt.Fprintln(os.Stderr, "  ▸ live events muted for interactive TUI; details are in summary/log")
	}
	passthroughHosts := passthroughHostsForCommand(childCmd, effectiveCodexPassthrough(flags))
	if len(passthroughHosts) > 0 && !flags.quiet {
		_, _ = fmt.Fprintln(os.Stderr, "  ▸ WARNING: codex passthrough enabled; chatgpt.com traffic is not body-inspected (use --no-codex-passthrough to disable)")
	}

	var recorder *replay.Recorder
	if cfg.SaveSession != "" {
		recorder, err = replay.NewRecorder(cfg.SaveSession)
		if err != nil {
			return err
		}
		defer recorder.Close()
	}
	var replayer *replay.Player
	if cfg.Replay != "" {
		replayer, err = replay.Load(cfg.Replay)
		if err != nil {
			return err
		}
	}
	var explainer *ui.Explainer
	if flags.explain {
		explainer = ui.NewExplainer(os.Stdin, os.Stderr)
	}

	guard := response.New(cfg.ResponseSanitize.Mode, sanitizer)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	proxyServer, err := proxy.New(proxy.Options{
		Addr:             fmt.Sprintf("127.0.0.1:%d", cfg.Port),
		Mode:             cfg.Mode,
		UpstreamProxy:    cfg.UpstreamProxy,
		PassthroughHosts: passthroughHosts,
		CACert:           caCert,
		Engine:           engine,
		Sanitizer:        sanitizer,
		Guard:            guard,
		Budget:           budgetController,
		UI:               inline,
		Log:              logWriter,
		Recorder:         recorder,
		Replayer:         replayer,
		Explainer:        explainer,
	})
	if err != nil {
		return err
	}
	if err := proxyServer.Start(ctx); err != nil {
		return err
	}

	runner := &supervisor.Runner{ProxyAddr: fmt.Sprintf("127.0.0.1:%d", cfg.Port), CAPath: caManager.CertPath()}
	runResult, runErr := runner.Run(ctx, childCmd)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = proxyServer.Stop(shutdownCtx)
	shutdownCancel()

	st := proxyServer.Stats()
	topHosts := toHostCounters(st.HostCounts)
	topBlocked := toHostCounters(st.BlockedHosts)
	inline.PrintSummary(ui.Summary{
		Duration:        proxyServer.Duration(),
		Requests:        st.Requests,
		Allowed:         st.Allowed,
		Blocked:         st.Blocked,
		Sanitized:       st.Sanitized,
		Errors:          st.Errors,
		SecretsRedacted: st.SecretsRedacted,
		SpentUSD:        budgetController.Spent(),
		BudgetUSD:       budgetController.Budget(),
		TopHosts:        topHosts,
		TopBlocked:      topBlocked,
	}, cfg.Log.Path)

	if runErr != nil {
		return runErr
	}
	if cfg.FailOnBlocked && st.Blocked > 0 {
		return exitError{code: 2, err: fmt.Errorf("blocked events detected: %d", st.Blocked)}
	}
	if runResult.ExitCode != 0 {
		return exitError{code: runResult.ExitCode, err: fmt.Errorf("child exited with code %d", runResult.ExitCode)}
	}
	return nil
}

func newWatchCmd(flags *cliFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Starts proxy without spawning a child process",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(flags.configPath)
			if err != nil {
				return err
			}
			if err := applyFlagOverrides(&cfg, flags); err != nil {
				return err
			}
			if !cfg.Sanitizers.Enabled {
				_, _ = fmt.Fprintln(os.Stderr, "WARNING: sanitization is disabled (--no-sanitize / AGENTWALL_NO_SANITIZE=1). Secrets may leak.")
			}

			appDir, err := config.AppDir()
			if err != nil {
				return err
			}
			caManager := ca.New(appDir)
			if err := caManager.Ensure(); err != nil {
				return err
			}
			caCert, err := caManager.TLSCertificate()
			if err != nil {
				return err
			}

			fmt.Printf("export HTTPS_PROXY=http://127.0.0.1:%d\n", cfg.Port)
			fmt.Printf("export HTTP_PROXY=http://127.0.0.1:%d\n", cfg.Port)
			fmt.Printf("export https_proxy=http://127.0.0.1:%d\n", cfg.Port)
			fmt.Printf("export http_proxy=http://127.0.0.1:%d\n", cfg.Port)
			fmt.Printf("export NODE_EXTRA_CA_CERTS=%s\n", caManager.CertPath())

			engine, err := rules.New(cfg.Mode, convertRuleConfigs(cfg.Rules))
			if err != nil {
				return err
			}
			sanitizer, err := sanitize.New(sanitize.Config{Enabled: cfg.Sanitizers.Enabled, MaxBodyBytes: cfg.Sanitizers.MaxBodyKB * 1024, Custom: convertCustomSanitizers(cfg.Sanitizers.Custom)})
			if err != nil {
				return err
			}
			if cfg.EnvGuard.Enabled {
				secrets, _ := sanitize.DiscoverEnvSecrets(".", cfg.EnvGuard.Discover, cfg.EnvGuard.MaxFileKB)
				sanitizer.SetEnvSecrets(secrets)
			}
			guard := response.New(cfg.ResponseSanitize.Mode, sanitizer)
			logWriter, err := auditlog.NewWriter(cfg.Log.Path, cfg.Log.MaxSizeMB, cfg.Log.Rotate, cfg.Log.MaxBackups, cfg.Log.MaxAgeDays, cfg.Log.Compress)
			if err != nil {
				return err
			}
			defer logWriter.Close()

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			server, err := proxy.New(proxy.Options{
				Addr:          fmt.Sprintf("127.0.0.1:%d", cfg.Port),
				Mode:          cfg.Mode,
				UpstreamProxy: cfg.UpstreamProxy,
				CACert:        caCert,
				Engine:        engine,
				Sanitizer:     sanitizer,
				Guard:         guard,
				Budget:        budget.New(cfg.Budget.USD, cfg.Budget.OnExceed),
				UI:            ui.NewInline(os.Stderr, flags.noColor, flags.json, flags.quiet),
				Log:           logWriter,
			})
			if err != nil {
				return err
			}
			if err := server.Start(ctx); err != nil {
				return err
			}
			<-ctx.Done()
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = server.Stop(stopCtx)
			stopCancel()
			return nil
		},
	}
	return cmd
}

func newReplayCmd(flags *cliFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replay <session.jsonl> -- <command> [args...]",
		Short: "Shortcut for run --replay",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return errors.New("replay requires session file and child command")
			}
			if strings.TrimSpace(args[1]) == "" {
				return errors.New("child command cannot be empty")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			flags.replay = args[0]
			return runAgentWall(flags, args[1:])
		},
	}
	return cmd
}

func newDoctorCmd(flags *cliFlags) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Runs local diagnostics for AgentWall environment",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(flags.configPath)
			if err != nil {
				return err
			}
			if err := applyFlagOverrides(&cfg, flags); err != nil {
				return err
			}
			report := doctor.Run(cfg)
			if jsonOut {
				fmt.Println(report.RenderJSON())
			} else {
				fmt.Print(report.RenderText())
			}
			if report.HasFailures() {
				return exitError{code: 1, err: errors.New("doctor found failing checks")}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON report")
	return cmd
}

func newCACmd(flags *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "ca", Short: "Manage local AgentWall CA"}
	cmd.AddCommand(&cobra.Command{Use: "path", RunE: func(cmd *cobra.Command, args []string) error {
		appDir, err := config.AppDir()
		if err != nil {
			return err
		}
		manager := ca.New(appDir)
		if err := manager.Ensure(); err != nil {
			return err
		}
		fmt.Println(manager.CertPath())
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "install", RunE: func(cmd *cobra.Command, args []string) error {
		appDir, err := config.AppDir()
		if err != nil {
			return err
		}
		manager := ca.New(appDir)
		if err := manager.Install(); err != nil {
			fmt.Fprintf(os.Stderr, "CA install failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "Fallback: export NODE_EXTRA_CA_CERTS=%s\n", manager.CertPath())
			return nil
		}
		fmt.Println("CA installed to trust store")
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "uninstall", RunE: func(cmd *cobra.Command, args []string) error {
		appDir, err := config.AppDir()
		if err != nil {
			return err
		}
		manager := ca.New(appDir)
		if err := manager.Uninstall(); err != nil {
			return err
		}
		fmt.Println("CA removed from trust store")
		return nil
	}})
	return cmd
}

func newRulesCmd(flags *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "Inspect active rules"}
	cmd.AddCommand(&cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(flags.configPath)
		if err != nil {
			return err
		}
		if err := applyFlagOverrides(&cfg, flags); err != nil {
			return err
		}
		fmt.Println("Builtin telemetry blocklist:")
		for _, host := range rules.BuiltinTelemetryBlocklist {
			fmt.Printf("- %s\n", host)
		}
		if len(cfg.Rules) > 0 {
			fmt.Println("\nUser rules:")
			for _, r := range cfg.Rules {
				fmt.Printf("- %s %s %s\n", r.ID, r.Action, r.Host)
			}
		}
		return nil
	}})

	var method string
	var body string
	test := &cobra.Command{
		Use:   "test <url>",
		Short: "Show matching rule for a synthetic request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(flags.configPath)
			if err != nil {
				return err
			}
			if err := applyFlagOverrides(&cfg, flags); err != nil {
				return err
			}
			u, err := url.Parse(args[0])
			if err != nil {
				return err
			}
			engine, err := rules.New(cfg.Mode, convertRuleConfigs(cfg.Rules))
			if err != nil {
				return err
			}
			bodyBytes := []byte(body)
			if strings.HasPrefix(body, "@") {
				raw, err := os.ReadFile(strings.TrimPrefix(body, "@"))
				if err != nil {
					return err
				}
				bodyBytes = raw
			}
			decision := engine.Decide(rules.Request{Method: strings.ToUpper(method), Host: u.Hostname(), Path: u.Path, RawQuery: u.RawQuery, Body: bodyBytes})
			fmt.Printf("action=%s source=%s rule=%s fields=%s\n", decision.Action, decision.DecisionSource, decision.MatchedRuleID, strings.Join(decision.MatchedFields, ","))
			if decision.Reason != "" {
				fmt.Printf("reason=%s\n", decision.Reason)
			}
			return nil
		},
	}
	test.Flags().StringVar(&method, "method", "GET", "HTTP method")
	test.Flags().StringVar(&body, "body", "", "request body (inline)")
	cmd.AddCommand(test)
	return cmd
}

func newLogCmd(flags *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "log", Short: "Inspect JSONL audit log"}
	tailCmd := &cobra.Command{Use: "tail", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(flags.configPath)
		if err != nil {
			return err
		}
		follow, _ := cmd.Flags().GetBool("follow")
		return auditlog.Tail(cfg.Log.Path, follow, func(line string) { fmt.Print(line) })
	}}
	tailCmd.Flags().BoolP("follow", "f", false, "follow file")

	grepCmd := &cobra.Command{Use: "grep <pattern>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(flags.configPath)
		if err != nil {
			return err
		}
		return auditlog.Grep(cfg.Log.Path, args[0], func(line string) { fmt.Print(line) })
	}}

	statsCmd := &cobra.Command{Use: "stats", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(flags.configPath)
		if err != nil {
			return err
		}
		st, err := auditlog.ComputeStats(cfg.Log.Path)
		if err != nil {
			return err
		}
		fmt.Printf("Requests:  %d\n", st.Requests)
		fmt.Printf("Allowed:   %d\n", st.Allowed)
		fmt.Printf("Blocked:   %d\n", st.Blocked)
		fmt.Printf("Sanitized: %d\n", st.Sanitized)
		fmt.Printf("Errors:    %d\n", st.Errors)
		fmt.Println("Top hosts:")
		for _, h := range auditlog.TopN(st.TopHosts, 10) {
			fmt.Printf("- %s: %d\n", h.Host, h.Count)
		}
		fmt.Println("Top blocked:")
		for _, h := range auditlog.TopN(st.TopBlocked, 10) {
			fmt.Printf("- %s: %d\n", h.Host, h.Count)
		}
		return nil
	}}
	cmd.AddCommand(tailCmd, grepCmd, statsCmd)
	return cmd
}

func newInitCmd(flags *cliFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write ~/.agentwall/config.yaml with defaults",
		RunE: func(cmd *cobra.Command, args []string) error {
			appDir, err := config.AppDir()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(appDir, 0o700); err != nil {
				return err
			}
			target := appDir + "/config.yaml"
			if _, err := os.Stat(target); err == nil {
				return fmt.Errorf("config already exists: %s", target)
			}
			if err := os.WriteFile(target, []byte(config.RenderDefaultYAML()), 0o600); err != nil {
				return err
			}
			fmt.Println(target)
			return nil
		},
	}
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print AgentWall build info",
		Run: func(cmd *cobra.Command, args []string) {
			meta := version.Full()
			fmt.Printf("version: %s\n", meta["version"])
			fmt.Printf("commit: %s\n", meta["commit"])
			fmt.Printf("build date: %s\n", meta["build_date"])
			fmt.Printf("go: %s\n", meta["go"])
		},
	}
}

func applyFlagOverrides(cfg *config.Config, flags *cliFlags) error {
	if flags.mode != "" {
		cfg.Mode = flags.mode
	}
	if flags.port != 0 {
		cfg.Port = flags.port
	}
	if flags.upstreamProxy != "" {
		cfg.UpstreamProxy = flags.upstreamProxy
	}
	if flags.responseSanitize != "" {
		cfg.ResponseSanitize.Mode = flags.responseSanitize
	}
	if flags.noSanitize {
		cfg.Sanitizers.Enabled = false
	}
	if flags.failOnBlocked {
		cfg.FailOnBlocked = true
	}
	if flags.saveSession != "" {
		cfg.SaveSession = flags.saveSession
	}
	if flags.replay != "" {
		cfg.Replay = flags.replay
	}
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	cfg.ResponseSanitize.Mode = strings.ToLower(strings.TrimSpace(cfg.ResponseSanitize.Mode))
	if cfg.Mode == "" {
		cfg.Mode = "balanced"
	}
	if cfg.Port == 0 {
		cfg.Port = config.DefaultPort
	}
	if cfg.ResponseSanitize.Mode != "" {
		switch cfg.ResponseSanitize.Mode {
		case "off", "detect", "sanitize", "block":
		default:
			cfg.ResponseSanitize.Mode = ""
		}
	}
	if cfg.ResponseSanitize.Mode == "" {
		switch cfg.Mode {
		case "loose":
			cfg.ResponseSanitize.Mode = "detect"
		case "strict":
			cfg.ResponseSanitize.Mode = "block"
		default:
			cfg.ResponseSanitize.Mode = "sanitize"
		}
	}
	return cfg.Validate()
}

func convertRuleConfigs(in []config.RuleConfig) []rules.Rule {
	out := make([]rules.Rule, 0, len(in))
	for _, r := range in {
		out = append(out, rules.Rule{
			ID:          r.ID,
			Action:      rules.Action(strings.ToLower(r.Action)),
			Host:        r.Host,
			Path:        r.Path,
			Method:      r.Method,
			BodyRegex:   r.BodyRegex,
			HeaderRegex: r.HeaderRegex,
			Source:      "user",
		})
	}
	return out
}

func convertCustomSanitizers(in []config.RulePattern) []sanitize.PatternDef {
	out := make([]sanitize.PatternDef, 0, len(in))
	for _, c := range in {
		out = append(out, sanitize.PatternDef{ID: c.ID, Pattern: c.Pattern, Replacement: c.Replacement})
	}
	return out
}

func toHostCounters(m map[string]int) []ui.HostCounter {
	out := make([]ui.HostCounter, 0, len(m))
	for host, count := range m {
		out = append(out, ui.HostCounter{Host: host, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Host < out[j].Host
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

func shouldMuteLiveEvents(flags *cliFlags, childCmd []string) bool {
	if flags == nil || flags.quiet || flags.json {
		return false
	}
	if len(childCmd) == 0 || !stdioLooksInteractive() {
		return false
	}
	return likelyInteractiveCommand(childCmd[0])
}

func stdioLooksInteractive() bool {
	return isCharDevice(os.Stdin) && isCharDevice(os.Stdout) && isCharDevice(os.Stderr)
}

func isCharDevice(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func likelyInteractiveCommand(command string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(command)))
	switch base {
	case "codex", "claude", "opencode", "aider", "gemini", "continue":
		return true
	default:
		return false
	}
}

func effectiveCodexPassthrough(flags *cliFlags) bool {
	if flags == nil {
		return false
	}
	if flags.noCodexPassthrough {
		return false
	}
	return flags.codexPassthrough
}

func passthroughHostsForCommand(childCmd []string, codexPassthrough bool) []string {
	if len(childCmd) == 0 {
		return nil
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(childCmd[0])))
	if codexPassthrough && base == "codex" {
		return []string{"chatgpt.com", ".chatgpt.com"}
	}
	return nil
}

// Package cmd implements the wick CLI commands and flags.
package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/krypsis-io/wick/internal/config"
	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/format"
	"github.com/krypsis-io/wick/internal/output"
	"github.com/krypsis-io/wick/internal/redact"
	"github.com/spf13/cobra"
)

var (
	flagFiles   []string
	flagDir     string
	flagOut     string
	flagStyle   string
	flagFormat  string
	flagSummary bool
)

var rootCmd = &cobra.Command{
	Use:   "wick",
	Short: "Fast, zero-config secret and PII redaction for any text stream",
	Long: `Wick detects and redacts secrets and PII from any text stream.
Pipe anything through it: cat logs.txt | wick`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          run,
}

func init() {
	rootCmd.Flags().StringSliceVar(&flagFiles, "file", nil, "input file(s) to redact")
	rootCmd.Flags().StringVar(&flagDir, "dir", "", "directory of files to redact")
	rootCmd.Flags().StringVar(&flagOut, "out", "", "output directory for --dir mode")
	rootCmd.Flags().StringVar(&flagStyle, "style", "", "redaction style: redacted, stars, or custom=\"...\"")
	rootCmd.Flags().StringVar(&flagFormat, "format", "", "output format: text, json")
	rootCmd.Flags().BoolVar(&flagSummary, "summary", false, "print redaction summary to stderr")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(_ *cobra.Command, _ []string) error {
	// Validate flag combinations.
	if flagDir != "" && len(flagFiles) > 0 {
		return fmt.Errorf("--dir and --file are mutually exclusive")
	}
	if flagOut != "" && flagDir == "" {
		return fmt.Errorf("--out is only valid with --dir")
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	style, err := resolveStyle(cfg)
	if err != nil {
		return err
	}
	detector, err := detect.New()
	if err != nil {
		return fmt.Errorf("detector: %w", err)
	}
	if len(cfg.CustomPatterns) > 0 {
		if err := detector.SetCustomPatterns(cfg.CustomPatterns); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}

	outputFormat, err := resolveFormat(cfg)
	if err != nil {
		return err
	}

	var foundCount int

	// Directory mode.
	if flagDir != "" {
		if flagOut == "" {
			return fmt.Errorf("--out is required with --dir")
		}
		n, err := processDir(flagDir, flagOut, detector, style, outputFormat)
		foundCount = n
		if err != nil {
			return err
		}
	} else if len(flagFiles) > 0 { // File mode.
		n, err := processFiles(flagFiles, detector, style, outputFormat)
		foundCount = n
		if err != nil {
			return err
		}
	} else {
		// Stdin mode (default).
		stat, err := os.Stdin.Stat()
		if err != nil {
			return fmt.Errorf("stdin: %w", err)
		}
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return fmt.Errorf("no input: pipe data to wick or use --file/--dir")
		}

		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}

		n, err := processInput(string(data), detector, style, outputFormat)
		foundCount = n
		if err != nil {
			return err
		}
	}

	if foundCount > 0 {
		os.Exit(1)
	}
	return nil
}

func processInput(input string, d *detect.Detector, style redact.Style, outputFmt string) (int, error) {
	redacted, findings := format.Process(input, d, style)

	if outputFmt == "json" {
		jsonOut, err := output.JSON(redacted, findings)
		if err != nil {
			return 0, err
		}
		fmt.Println(jsonOut)
	} else {
		// format.Process already redacted the text; for TTY colorization
		// we re-process from the original input.
		fmt.Print(output.Terminal(input, redacted, findings, style))
	}

	if flagSummary {
		output.Summary(os.Stderr, findings)
	}

	return len(findings), nil
}

func processFiles(files []string, d *detect.Detector, style redact.Style, outputFmt string) (int, error) {
	total := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return total, fmt.Errorf("reading %s: %w", f, err)
		}
		n, err := processInput(string(data), d, style, outputFmt)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func processDir(dir, outDir string, d *detect.Detector, style redact.Style, _ string) (int, error) {
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return 0, fmt.Errorf("resolving dir path: %w", err)
	}
	outAbs, err := filepath.Abs(outDir)
	if err != nil {
		return 0, fmt.Errorf("resolving out path: %w", err)
	}
	if outAbs == dirAbs || strings.HasPrefix(outAbs, dirAbs+string(os.PathSeparator)) {
		return 0, fmt.Errorf("--out must not be inside --dir (would recurse into output)")
	}

	total := 0
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("computing relative path for %s: %w", path, err)
		}
		outPath := filepath.Join(outDir, relPath)

		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return err
		}

		redacted, findings := format.Process(string(data), d, style)
		total += len(findings)

		if err := os.WriteFile(outPath, []byte(redacted), info.Mode()); err != nil {
			return fmt.Errorf("writing %s: %w", outPath, err)
		}

		if flagSummary && len(findings) > 0 {
			fmt.Fprintf(os.Stderr, "%s: ", relPath)
			output.Summary(os.Stderr, findings)
		}
		return nil
	})
	return total, err
}

func resolveStyle(cfg *config.Config) (redact.Style, error) {
	s := cfg.Style
	if flagStyle != "" {
		s = flagStyle
	}
	switch {
	case s == "" || s == "redacted":
		return redact.StyleRedacted, nil
	case s == "stars":
		return redact.StyleStars, nil
	case strings.HasPrefix(s, "custom="):
		redact.SetCustomReplacement(strings.TrimPrefix(s, "custom="))
		return redact.CustomStyle(), nil
	default:
		return 0, fmt.Errorf("unknown style %q: use redacted, stars, or custom=\"...\"", s)
	}
}

func resolveFormat(cfg *config.Config) (string, error) {
	f := cfg.Format
	if flagFormat != "" {
		f = flagFormat
	}
	switch f {
	case "", "text":
		return "text", nil
	case "json":
		return "json", nil
	default:
		return "", fmt.Errorf("unknown format %q: use text or json", f)
	}
}

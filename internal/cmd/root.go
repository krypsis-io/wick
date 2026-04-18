// Package cmd implements the wick CLI commands and flags.
package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/krypsis-io/wick/internal/config"
	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/format"
	"github.com/krypsis-io/wick/internal/output"
	"github.com/krypsis-io/wick/redact"
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

var errFindingsPresent = errors.New("findings present")

const maxStdinBytes = 10 * 1024 * 1024

type runOptions struct {
	dir   string
	files []string
	out   string
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if !errors.Is(err, errFindingsPresent) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func run(_ *cobra.Command, _ []string) error {
	if err := validateRunFlags(); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	replacer, err := resolveReplacer(cfg)
	if err != nil {
		return err
	}

	detector, err := newDetector(cfg)
	if err != nil {
		return err
	}

	outputFormat, err := resolveFormat(cfg)
	if err != nil {
		return err
	}

	opts := runOptions{
		dir:   flagDir,
		files: flagFiles,
		out:   flagOut,
	}

	foundCount, err := executeRunMode(opts, detector, replacer, outputFormat)
	if err != nil {
		return err
	}

	if foundCount > 0 {
		return errFindingsPresent
	}
	return nil
}

func validateRunFlags() error {
	if flagDir != "" && len(flagFiles) > 0 {
		return fmt.Errorf("--dir and --file are mutually exclusive")
	}
	if flagOut != "" && flagDir == "" {
		return fmt.Errorf("--out is only valid with --dir")
	}
	return nil
}

func newDetector(cfg *config.Config) (*detect.Detector, error) {
	detector, err := detect.New()
	if err != nil {
		return nil, fmt.Errorf("detector: %w", err)
	}
	if len(cfg.CustomPatterns) == 0 {
		return detector, nil
	}
	if err := detector.SetCustomPatterns(cfg.CustomPatterns); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return detector, nil
}

func executeRunMode(opts runOptions, detector *detect.Detector, replacer redact.Replacer, outputFormat string) (int, error) {
	switch {
	case opts.dir != "":
		return executeDirMode(detector, replacer, opts.dir, opts.out, outputFormat)
	case len(opts.files) > 0:
		return processFiles(opts.files, detector, replacer, outputFormat)
	default:
		return processStdin(detector, replacer, outputFormat)
	}
}

func executeDirMode(detector *detect.Detector, replacer redact.Replacer, dir, out, outputFormat string) (int, error) {
	if out == "" {
		return 0, fmt.Errorf("--out is required with --dir")
	}
	if outputFormat == "json" {
		return 0, fmt.Errorf("--format json is not supported with --dir")
	}
	return processDir(dir, out, detector, replacer, outputFormat)
}

func processStdin(detector *detect.Detector, replacer redact.Replacer, outputFormat string) (int, error) {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return 0, fmt.Errorf("stdin: %w", err)
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return 0, fmt.Errorf("no input: pipe data to wick or use --file/--dir")
	}

	reader := io.LimitReader(os.Stdin, maxStdinBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return 0, fmt.Errorf("reading stdin: %w", err)
	}
	if len(data) > maxStdinBytes {
		return 0, fmt.Errorf("stdin exceeds maximum size of %d bytes", maxStdinBytes)
	}

	return processInput(string(data), detector, replacer, outputFormat)
}

func processInput(input string, d *detect.Detector, replacer redact.Replacer, outputFmt string) (int, error) {
	redacted, findings := format.Process(input, d, replacer)

	if outputFmt == "json" {
		jsonOut, err := output.JSON(redacted, findings)
		if err != nil {
			return 0, err
		}
		fmt.Println(jsonOut)
	} else {
		// format.Process already redacted the text; for TTY colorization
		// we re-process from the original input.
		fmt.Print(output.Terminal(input, redacted, findings, replacer))
	}

	if flagSummary {
		output.Summary(os.Stderr, findings)
	}

	return len(findings), nil
}

func processFiles(files []string, d *detect.Detector, replacer redact.Replacer, outputFmt string) (int, error) {
	total := 0
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			return total, fmt.Errorf("reading %s: %w", f, err)
		}
		if !info.Mode().IsRegular() {
			return total, fmt.Errorf("%s is not a regular file", f)
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return total, fmt.Errorf("reading %s: %w", f, err)
		}
		n, err := processInput(string(data), d, replacer, outputFmt)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func processDir(dir, outDir string, d *detect.Detector, replacer redact.Replacer, _ string) (int, error) {
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

		redacted, findings := format.Process(string(data), d, replacer)
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

func resolveReplacer(cfg *config.Config) (redact.Replacer, error) {
	s := cfg.Style
	if flagStyle != "" {
		s = flagStyle
	}
	switch {
	case s == "" || s == "redacted":
		return redact.Redacted, nil
	case s == "stars":
		return redact.Stars, nil
	case strings.HasPrefix(s, "custom="):
		return redact.Custom(strings.TrimPrefix(s, "custom=")), nil
	default:
		return nil, fmt.Errorf("unknown style %q: use redacted, stars, or custom=\"...\"", s)
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

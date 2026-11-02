package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/term"

	"pq/internal/client"
	"pq/internal/config"
	"pq/internal/daemon"
	"pq/internal/protocol"
	"pq/internal/secure"
)

func main() {
	syscall.Umask(0077)
	if err := secure.Harden(); err != nil {
		fmt.Fprintln(os.Stderr, "pq: cannot apply process safeguards:", err)
		os.Exit(1)
	}
	if err := run(os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "pq:", err)
		os.Exit(1)
	}
}

func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	return f
}
func parse(f *flag.FlagSet, args []string, n int) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != n {
		return errors.New("unexpected or missing arguments; use --help")
	}
	return nil
}
func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func run(args []string) error {
	paths, err := config.Defaults()
	if err != nil {
		return err
	}
	f := flags("pq")
	f.StringVar(&paths.DataDir, "data-dir", paths.DataDir, "vault directory (daemon only)")
	f.StringVar(&paths.Socket, "socket", paths.Socket, "daemon Unix socket")
	f.StringVar(&paths.Config, "config", paths.Config, "daemon JSON configuration")
	f.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: pq [global options] COMMAND [options]

Commands:
  daemon                       Run the locked daemon in the foreground
  init, unlock [--ttl 15m]      Initialize or unlock the vault
  lock, status                 Lock the vault or inspect its state
  add login|secret [options]   Save a login or generic secret
  edit ID [options]            Update an entry
  list [--json], search QUERY  List metadata, never secret values
  get ID [--field FIELD]       Print an entry or a specific secret field
  delete ID [--yes]            Delete an entry
  passwd                       Change the master password
  backup DESTINATION           Create an encrypted backup (must not exist)
  import firefox [options]    Import a CSV export or an NSS profile
  firefox install [options]   Register the Firefox native-messaging host

Global options must precede the command. Command options follow its positional
arguments. Use COMMAND --help for options. Secrets are prompted on /dev/tty;
--password-stdin / --text-stdin explicitly enable piped secret input.`)
		f.PrintDefaults()
	}
	if err = f.Parse(args); err != nil {
		return err
	}
	args = f.Args()
	if len(args) == 0 || args[0] == "help" {
		f.Usage()
		return nil
	}
	for _, p := range []*string{&paths.DataDir, &paths.Socket, &paths.Config} {
		*p, err = filepath.Abs(*p)
		if err != nil {
			return err
		}
	}
	command, args := args[0], args[1:]
	switch command {
	case "daemon":
		settings, err := config.Load(paths.Config)
		if err != nil {
			return err
		}
		f := flags("daemon")
		f.StringVar(&settings.UnlockTTL, "ttl", settings.UnlockTTL, "default absolute unlock TTL")
		if err := parse(f, args, 0); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		server := daemon.Server{Paths: paths, Settings: settings}
		return server.Run(ctx)
	case "init", "unlock", "passwd":
		return auth(paths, command, args)
	case "status", "lock":
		if err := parse(flags(command), args, 0); err != nil {
			return err
		}
		response, err := client.Call(paths.Socket, protocol.Request{Op: command})
		if err != nil {
			return err
		}
		return printJSON(response.Status)
	case "add", "edit", "list", "search", "get", "delete":
		return entries(paths, command, args)
	case "backup":
		if err := parse(flags(command), args, 1); err != nil {
			return err
		}
		path, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		_, err = client.Call(paths.Socket, protocol.Request{Op: "backup", Destination: path})
		if err == nil {
			fmt.Fprintln(os.Stdout, "Encrypted backup created:", path)
		}
		return err
	case "import":
		return importFirefox(paths, args)
	case "firefox":
		return installFirefox(args)
	default:
		return fmt.Errorf("unknown command %q; use pq help", command)
	}
}

func auth(paths config.Paths, command string, args []string) error {
	f := flags(command)
	stdin := f.Bool("password-stdin", false, "read master password from stdin instead of a terminal")
	ttl := ""
	if command != "passwd" {
		f.StringVar(&ttl, "ttl", "", "absolute unlock TTL (defaults to daemon configuration)")
	}
	if err := parse(f, args, 0); err != nil {
		return err
	}
	var password []byte
	var err error
	if *stdin {
		password, err = readInput(4096, true)
	} else {
		label := "Master password: "
		if command == "passwd" {
			label = "New master password: "
		}
		password, err = promptSecret(label)
	}
	if err != nil {
		return err
	}
	defer secure.Wipe(password)
	if command != "unlock" && !*stdin {
		confirmation, err := promptSecret("Confirm master password: ")
		if err != nil {
			return err
		}
		defer secure.Wipe(confirmation)
		if !bytes.Equal(password, confirmation) {
			return errors.New("master passwords do not match")
		}
	}
	response, err := client.Call(paths.Socket, protocol.Request{Op: command, Password: password, TTL: ttl})
	if err != nil {
		return err
	}
	if response.Status != nil {
		return printJSON(response.Status)
	}
	fmt.Fprintln(os.Stdout, "Master password changed. Existing backups still require their original password.")
	return nil
}

func promptSecret(label string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("no controlling terminal; use an explicit stdin option for piped input")
	}
	defer tty.Close()
	fmt.Fprint(tty, label)
	password, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return password, err
}

func readInput(limit int, trimNewline bool) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, int64(limit+2)))
	if err != nil {
		secure.Wipe(data)
		return nil, err
	}
	if trimNewline {
		data = bytes.TrimSuffix(data, []byte("\n"))
		data = bytes.TrimSuffix(data, []byte("\r"))
	}
	if len(data) > limit {
		secure.Wipe(data)
		return nil, errors.New("stdin exceeds size limit")
	}
	return data, nil
}

func confirm(label string) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("confirmation requires a terminal; use --yes to confirm explicitly")
	}
	defer tty.Close()
	fmt.Fprint(tty, label+" [y/N] ")
	var answer string
	if _, err := fmt.Fscanln(tty, &answer); err != nil {
		return errors.New("cancelled")
	}
	if answer != "y" && answer != "Y" {
		return errors.New("cancelled")
	}
	return nil
}

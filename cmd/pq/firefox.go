package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"pq/internal/client"
	"pq/internal/config"
	"pq/internal/firefox"
	"pq/internal/model"
	"pq/internal/protocol"
	"pq/internal/secure"
)

func importFirefox(paths config.Paths, args []string) error {
	if len(args) == 0 || args[0] != "firefox" {
		return errors.New("usage: pq import firefox --csv FILE or --profile DIRECTORY [--duplicates skip|update|error] [--yes]")
	}
	f := flags("import firefox")
	csvPath := f.String("csv", "", "Firefox plaintext CSV export")
	profile := f.String("profile", "", "Firefox profile directory (close Firefox first)")
	duplicates := f.String("duplicates", "skip", "duplicate policy: skip, update, error")
	yes := f.Bool("yes", false, "confirm import without prompting")
	if err := parse(f, args[1:], 0); err != nil {
		return err
	}
	if (*csvPath == "") == (*profile == "") {
		return errors.New("choose exactly one of --csv or --profile")
	}
	status, err := client.Call(paths.Socket, protocol.Request{Op: "status"})
	if err != nil {
		return err
	}
	if status.Status.Locked {
		return errors.New("vault is locked; run pq unlock")
	}
	var entries []model.Entry
	if *csvPath != "" {
		fmt.Fprintln(os.Stderr, "Warning: Firefox CSV exports contain plaintext passwords. Remove the export when finished; deletion does not guarantee secure erasure.")
		file, err := os.Open(*csvPath)
		if err != nil {
			return err
		}
		defer file.Close()
		entries, err = firefox.CSV(file)
		if err != nil {
			return err
		}
	} else {
		entries, err = firefox.Profile(*profile, nil)
		if errors.Is(err, firefox.ErrPrimaryPassword) {
			password, promptErr := promptSecret("Firefox Primary Password: ")
			if promptErr != nil {
				return promptErr
			}
			defer secure.Wipe(password)
			entries, err = firefox.Profile(*profile, password)
		}
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "Parsed %d login entries; duplicate policy: %s.\n", len(entries), *duplicates)
	if !*yes {
		if err := confirm("Import these logins?"); err != nil {
			return err
		}
	}
	response, err := client.Call(paths.Socket, protocol.Request{Op: "import", Entries: entries, Duplicates: *duplicates})
	if err != nil {
		return err
	}
	return printJSON(response.Import)
}

func installFirefox(args []string) error {
	if len(args) == 0 || args[0] != "install" {
		return errors.New("usage: pq firefox install [--host /absolute/path/to/pq-native]")
	}
	f := flags("firefox install")
	host := f.String("host", "", "native host executable (defaults to pq-native beside pq or on PATH)")
	if err := parse(f, args[1:], 0); err != nil {
		return err
	}
	if *host == "" {
		if exe, err := os.Executable(); err == nil {
			candidate := filepath.Join(filepath.Dir(exe), "pq-native")
			if _, err := os.Stat(candidate); err == nil {
				*host = candidate
			}
		}
		if *host == "" {
			found, err := exec.LookPath("pq-native")
			if err != nil {
				return errors.New("pq-native not found; install it or specify --host")
			}
			*host = found
		}
	}
	absolute, err := filepath.Abs(*host)
	if err != nil {
		return err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("native host must be an executable file")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".mozilla", "native-messaging-hosts")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	manifest := struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Path        string   `json:"path"`
		Type        string   `json:"type"`
		Allowed     []string `json:"allowed_extensions"`
	}{"pq", "pq password manager", absolute, "stdio", []string{"pq@local"}}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".pq-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	destination := filepath.Join(dir, "pq.json")
	if err = os.Rename(tmp.Name(), destination); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "Registered Firefox native host:", destination)
	fmt.Fprintln(os.Stdout, "Load extension/manifest.json through about:debugging for development; a signed extension is required for persistent installation on standard Firefox.")
	return nil
}

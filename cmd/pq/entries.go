package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"pq/internal/client"
	"pq/internal/config"
	"pq/internal/model"
	"pq/internal/protocol"
	"pq/internal/secure"
)

func entries(paths config.Paths, command string, args []string) error {
	switch command {
	case "list", "search":
		query := ""
		if command == "search" {
			if len(args) == 0 {
				return errors.New("usage: pq search QUERY [--json]")
			}
			query, args = args[0], args[1:]
		}
		f := flags(command)
		asJSON := f.Bool("json", false, "print metadata as JSON")
		if err := parse(f, args, 0); err != nil {
			return err
		}
		response, err := client.Call(paths.Socket, protocol.Request{Op: "list", Query: query})
		if err != nil {
			return err
		}
		if *asJSON {
			if response.Entries == nil {
				response.Entries = []model.Entry{}
			}
			return printJSON(response.Entries)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tKIND\tTITLE\tUSERNAME\tORIGINS")
		for _, e := range response.Entries {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", e.ID, e.Kind, strconv.Quote(e.Title), strconv.Quote(e.Username), strconv.Quote(strings.Join(e.Origins, ", ")))
		}
		return w.Flush()
	case "get":
		if len(args) == 0 {
			return errors.New("usage: pq get ID [--field password|text|username|notes|json]")
		}
		id, args := args[0], args[1:]
		f := flags("get")
		field := f.String("field", "json", "field to print (json, password, text, username, notes)")
		if err := parse(f, args, 0); err != nil {
			return err
		}
		response, err := client.Call(paths.Socket, protocol.Request{Op: "get", ID: id})
		if err != nil {
			return err
		}
		switch *field {
		case "json":
			return printJSON(response.Entry)
		case "password":
			fmt.Fprint(os.Stdout, response.Entry.Password)
		case "text":
			fmt.Fprint(os.Stdout, response.Entry.Text)
		case "username":
			fmt.Fprint(os.Stdout, response.Entry.Username)
		case "notes":
			fmt.Fprint(os.Stdout, response.Entry.Notes)
		default:
			return errors.New("unknown output field")
		}
		return nil
	case "delete":
		if len(args) == 0 {
			return errors.New("usage: pq delete ID [--yes]")
		}
		id, args := args[0], args[1:]
		f := flags("delete")
		yes := f.Bool("yes", false, "confirm deletion")
		if err := parse(f, args, 0); err != nil {
			return err
		}
		if !*yes {
			if err := confirm("Permanently delete this entry?"); err != nil {
				return err
			}
		}
		_, err := client.Call(paths.Socket, protocol.Request{Op: "delete", ID: id})
		return err
	case "add", "edit":
		return putEntry(paths, command, args)
	}
	return errors.New("unknown entry command")
}

func putEntry(paths config.Paths, command string, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: pq add login|secret [options], or pq edit ID [options]")
	}
	var e model.Entry
	if command == "add" {
		e.Kind = args[0]
		if e.Kind != "login" && e.Kind != "secret" {
			return errors.New("entry kind must be login or secret")
		}
	} else {
		response, err := client.Call(paths.Socket, protocol.Request{Op: "get", ID: args[0]})
		if err != nil {
			return err
		}
		e = *response.Entry
	}
	args = args[1:]
	f := flags(command)
	title := f.String("title", e.Title, "entry title")
	username := f.String("username", e.Username, "login username")
	urls := f.String("url", strings.Join(e.Origins, ","), "comma-separated website URLs")
	tags := f.String("tags", strings.Join(e.Tags, ","), "comma-separated tags")
	passwordStdin := f.Bool("password-stdin", false, "read login password from stdin (removes one trailing newline)")
	textStdin := f.Bool("text-stdin", false, "read generic secret text exactly from stdin")
	prompt := f.Bool("prompt", false, "prompt for a replacement password or secret")
	jsonStdin := f.Bool("json-stdin", false, "read a complete entry JSON object from stdin")
	if err := parse(f, args, 0); err != nil {
		return err
	}
	if *jsonStdin {
		if f.NFlag() != 1 {
			return errors.New("--json-stdin cannot be combined with other entry options")
		}
		data, err := readInput(4<<20, false)
		if err != nil {
			return err
		}
		defer secure.Wipe(data)
		id, kind := e.ID, e.Kind
		e = model.Entry{}
		if err := json.Unmarshal(data, &e); err != nil {
			return errors.New("invalid entry JSON")
		}
		e.ID = id
		if e.Kind == "" {
			e.Kind = kind
		}
	} else {
		if *passwordStdin && *textStdin || (*prompt && (*passwordStdin || *textStdin)) {
			return errors.New("choose one secret input method")
		}
		e.Title, e.Username = *title, *username
		e.Origins = split(*urls)
		e.Tags = split(*tags)
		if *passwordStdin && e.Kind != "login" || *textStdin && e.Kind != "secret" {
			return errors.New("stdin option does not match entry kind")
		}
		if *passwordStdin || *textStdin || *prompt || command == "add" {
			var data []byte
			var err error
			if *passwordStdin || *textStdin {
				data, err = readInput(model.MaxSecret, *passwordStdin)
			} else {
				label := "Password: "
				if e.Kind == "secret" {
					label = "Secret text (single line; use --text-stdin for multiline): "
				}
				data, err = promptSecret(label)
			}
			if err != nil {
				return err
			}
			defer secure.Wipe(data)
			if e.Kind == "login" {
				e.Password = string(data)
			} else {
				e.Text = string(data)
			}
		}
		if command == "edit" && f.NFlag() == 0 {
			return errors.New("supply fields to change, --prompt, or --json-stdin")
		}
	}
	if err := e.Validate(); err != nil {
		return err
	}
	response, err := client.Call(paths.Socket, protocol.Request{Op: "put", Entry: &e})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, response.Entry.ID)
	return nil
}

func split(raw string) []string {
	result := []string{}
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			result = append(result, s)
		}
	}
	return result
}

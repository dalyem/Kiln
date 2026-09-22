package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"

	"github.com/kiln-dev/kiln/internal/workspace"
)

func workspaceCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kiln workspace capture --repo PATH --output FILE | kiln workspace inspect --input FILE")
	}
	flags := flag.NewFlagSet("workspace "+args[0], flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	switch args[0] {
	case "capture":
		repo := flags.String("repo", "", "Git working tree")
		output := flags.String("output", "", "new snapshot file")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *repo == "" || *output == "" {
			return errors.New("usage: kiln workspace capture --repo PATH --output FILE")
		}
		summary, err := workspace.CaptureFile(*repo, *output)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(summary)
	case "inspect":
		input := flags.String("input", "", "snapshot file")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *input == "" {
			return errors.New("usage: kiln workspace inspect --input FILE")
		}
		summary, err := workspace.InspectFile(*input)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(summary)
	default:
		return errors.New("usage: kiln workspace capture --repo PATH --output FILE | kiln workspace inspect --input FILE")
	}
}

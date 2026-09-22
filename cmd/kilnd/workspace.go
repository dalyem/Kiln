package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"

	"github.com/kiln-dev/kiln/internal/workspace"
)

func workspaceCommand(args []string) error {
	if len(args) == 0 || args[0] != "materialize" {
		return errors.New("usage: kilnd workspace materialize --input FILE --destination ABSENT_DIR")
	}
	flags := flag.NewFlagSet("workspace materialize", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	input := flags.String("input", "", "snapshot file")
	destination := flags.String("destination", "", "new workspace directory")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *input == "" || *destination == "" {
		return errors.New("usage: kilnd workspace materialize --input FILE --destination ABSENT_DIR")
	}
	summary, err := workspace.MaterializeFile(*input, *destination)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(summary)
}

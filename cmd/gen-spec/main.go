// gen-spec translates a browserleaks raw capture JSON into utls
// ClientHelloSpec JSON format.
//
// Usage: go run cmd/gen-spec/main.go <capture.json> [output.json]
package main

import (
	"fmt"
	"os"

	"github.com/parroteer/parroteer/internal/specgen"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: gen-spec <capture.json> [output.json]\n")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	captureJSON, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", inputFile, err)
		os.Exit(1)
	}

	specJSON, err := specgen.Generate(captureJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate: %v\n", err)
		os.Exit(1)
	}

	if len(os.Args) >= 3 {
		outputFile := os.Args[2]
		if err := os.WriteFile(outputFile, specJSON, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", outputFile, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Spec written to %s\n", outputFile)
	} else {
		fmt.Println(string(specJSON))
	}
}

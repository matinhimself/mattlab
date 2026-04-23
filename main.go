package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/itsmatinhimself/mattlab/config"
	"github.com/itsmatinhimself/mattlab/proxy"
)

var version = "dev"

func main() {
	configPath := flag.String("c", "config.json", "path to config file")
	showVersion := flag.Bool("v", false, "print version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mattlab %s\n", version)
		os.Exit(0)
	}

	absPath, err := filepath.Abs(*configPath)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}

	cfg, err := config.Load(absPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	cfgDir := filepath.Dir(absPath)

	orch, err := proxy.NewOrchestrator(cfg, cfgDir)
	if err != nil {
		log.Fatalf("init: %v", err)
	}

	if err := orch.Run(); err != nil {
		log.Fatalf("run: %v", err)
	}
}

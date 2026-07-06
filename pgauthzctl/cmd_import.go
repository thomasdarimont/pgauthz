package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// cmdImport loads a model file into an existing store.
func cmdImport(args []string) error {
	fs, dsn := newFlags("model import")
	store := fs.String("store", "", "target store (required)")
	pos := parseAll(fs, args)
	if *store == "" || len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl model import <model.fga|model.json> --store <store>")
	}

	modelJSON, warnings, err := loadModelJSON(pos[0])
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Println("WARN:", w)
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	var report map[string]any
	if err := queryJSON(ctx, conn, &report,
		"SELECT authz.import_openfga_model($1, $2::jsonb)", *store, modelJSON); err != nil {
		return err
	}
	fmt.Println(prettyJSON(report))
	return nil
}

// cmdPublish imports a model file into a scratch store and publishes it as
// the next immutable registry version (the git-file → registry pipeline).
func cmdPublish(args []string) error {
	fs, dsn := newFlags("model publish")
	name := fs.String("name", "", "registry model name (required)")
	message := fs.String("message", "", "version description (e.g. the git SHA)")
	viaStore := fs.String("via-store", "", "existing store to publish through (default: ephemeral scratch store)")
	pos := parseAll(fs, args)
	if *name == "" || len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl model publish <model.fga|model.json> --name <model> [--message m]")
	}

	modelJSON, warnings, err := loadModelJSON(pos[0])
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Println("WARN:", w)
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	store := *viaStore
	if store == "" {
		b := make([]byte, 4)
		rand.Read(b)
		store = "pgauthzctl_pub_" + hex.EncodeToString(b)
		if _, err := conn.Exec(ctx, "SELECT authz.create_store($1, 'pgauthzctl publish scratch')", store); err != nil {
			return err
		}
		defer conn.Exec(context.Background(), "SELECT authz.delete_store($1)", store)
	}

	var report map[string]any
	if err := queryJSON(ctx, conn, &report,
		"SELECT authz.import_openfga_model($1, $2::jsonb)", store, modelJSON); err != nil {
		return err
	}

	var version int
	if err := conn.QueryRow(ctx,
		"SELECT authz.publish_model($1, $2, nullif($3, ''))",
		*name, store, *message).Scan(&version); err != nil {
		return err
	}
	fmt.Printf("published %s@%d (rules: %v, type restrictions: %v)\n",
		*name, version, report["rules_imported"], report["type_restrictions_imported"])
	return nil
}

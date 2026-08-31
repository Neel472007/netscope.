// Package web embeds the dashboard HTML/CSS/JS files into the Go binary.
// This allows NetScope to serve its dashboard from a single executable
// with zero external file dependencies.
package web

import "embed"

//go:embed *.html *.css *.js
var Static embed.FS

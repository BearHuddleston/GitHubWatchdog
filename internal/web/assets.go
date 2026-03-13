package web

import "embed"

//go:embed templates/*.html static/styles.css static/js/*.js
var embeddedAssets embed.FS

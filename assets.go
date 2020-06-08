package main

import (
	_ "github.com/jteeuwen/go-bindata"
)

//go:generate go run github.com/jteeuwen/go-bindata/go-bindata --pkg main static/... templates/... email/...

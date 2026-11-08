package main

import (
	_ "github.com/MKrupauskas/coredns/experimental/iterative"
	"github.com/coredns/coredns/coremain"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/log"
)

func main() { coremain.Run() }

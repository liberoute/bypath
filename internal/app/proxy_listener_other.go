//go:build !linux

package app

import "github.com/liberoute/bypath/internal/serviceop"

func checkSamePort(int) error { return serviceop.ErrUnsupported }

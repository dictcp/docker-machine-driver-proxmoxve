package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	proxmoxve "github.com/mhermosi/docker-machine-driver-proxmoxve/proxmoxve"
)

func main() {
	plugin.RegisterDriver(proxmoxve.NewDriver("default", ""))
}

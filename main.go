package dockermachinedriverproxmoxve

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	proxmox "github.com/mhermosi/docker-machine-driver-proxmoxve/proxmoxve"
)

func main() {
	plugin.RegisterDriver(proxmox.NewDriver("", ""))
}

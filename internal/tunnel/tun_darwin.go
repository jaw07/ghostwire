//go:build darwin

package tunnel

import (
	"fmt"
	"net/netip"
	"os/exec"
)

// configureTunnel configures the TUN interface on macOS
func configureTunnel(ifname string, ip netip.Addr, subnet netip.Prefix) error {
	// Set IP address
	// On macOS, we need to specify both local and destination addresses for point-to-point
	if err := runCommand("ifconfig", ifname, "inet", ip.String(), ip.String(), "netmask", "255.255.255.255", "up"); err != nil {
		return fmt.Errorf("set IP address: %w", err)
	}

	// Add route for mesh subnet
	// Use the interface name as the gateway for utun devices
	if err := runCommand("route", "-n", "add", "-net", subnet.String(), "-interface", ifname); err != nil {
		// Route might already exist, try to replace
		if err := runCommand("route", "-n", "change", "-net", subnet.String(), "-interface", ifname); err != nil {
			return fmt.Errorf("add route: %w", err)
		}
	}

	return nil
}

// removeTunnel removes tunnel configuration on macOS
func removeTunnel(ifname string, subnet netip.Prefix) error {
	// Remove route
	_ = runCommand("route", "-n", "delete", "-net", subnet.String())

	// Interface is automatically cleaned up when closed
	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(output))
	}
	return nil
}

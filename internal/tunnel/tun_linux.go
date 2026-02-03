//go:build linux

package tunnel

import (
	"fmt"
	"net/netip"
	"os/exec"
)

// configureTunnel configures the TUN interface on Linux
func configureTunnel(ifname string, ip netip.Addr, subnet netip.Prefix) error {
	// Set IP address using ip command
	ipWithPrefix := fmt.Sprintf("%s/%d", ip.String(), subnet.Bits())
	if err := runCommand("ip", "addr", "add", ipWithPrefix, "dev", ifname); err != nil {
		// Address might already exist, try to replace
		_ = runCommand("ip", "addr", "del", ipWithPrefix, "dev", ifname)
		if err := runCommand("ip", "addr", "add", ipWithPrefix, "dev", ifname); err != nil {
			return fmt.Errorf("set IP address: %w", err)
		}
	}

	// Bring interface up
	if err := runCommand("ip", "link", "set", ifname, "up"); err != nil {
		return fmt.Errorf("bring interface up: %w", err)
	}

	// Add route for mesh subnet (the ip addr command usually adds this automatically)
	// Only needed if routing through a different interface
	if err := runCommand("ip", "route", "add", subnet.String(), "dev", ifname); err != nil {
		// Route might already exist via the address assignment
		// This is not an error
	}

	return nil
}

// removeTunnel removes tunnel configuration on Linux
func removeTunnel(ifname string, subnet netip.Prefix) error {
	// Remove route
	_ = runCommand("ip", "route", "del", subnet.String(), "dev", ifname)

	// Bring interface down
	_ = runCommand("ip", "link", "set", ifname, "down")

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

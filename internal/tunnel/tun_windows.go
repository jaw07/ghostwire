//go:build windows

package tunnel

import (
	"fmt"
	"net/netip"
	"os/exec"
)

// configureTunnel configures the TUN interface on Windows
func configureTunnel(ifname string, ip netip.Addr, subnet netip.Prefix) error {
	// On Windows, we use netsh to configure the interface
	// The interface name from wintun might be different

	// Set IP address
	prefixLen := subnet.Bits()
	mask := prefixToMask(prefixLen)

	if err := runCommand("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", ifname),
		"source=static",
		fmt.Sprintf("addr=%s", ip.String()),
		fmt.Sprintf("mask=%s", mask),
	); err != nil {
		return fmt.Errorf("set IP address: %w", err)
	}

	// Add route for mesh subnet
	if err := runCommand("route", "add", subnet.Masked().Addr().String(),
		"mask", mask,
		ip.String(),
	); err != nil {
		// Route might already exist
	}

	return nil
}

// removeTunnel removes tunnel configuration on Windows
func removeTunnel(ifname string, subnet netip.Prefix) error {
	mask := prefixToMask(subnet.Bits())
	_ = runCommand("route", "delete", subnet.Masked().Addr().String(), "mask", mask)
	return nil
}

func prefixToMask(bits int) string {
	// Convert prefix length to dotted decimal mask
	mask := uint32(0xffffffff) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d",
		(mask>>24)&0xff,
		(mask>>16)&0xff,
		(mask>>8)&0xff,
		mask&0xff,
	)
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(output))
	}
	return nil
}

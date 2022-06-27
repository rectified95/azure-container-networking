// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package platform

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/Azure/azure-container-networking/log"
	"golang.org/x/sys/windows"
)

const (
	// CNMRuntimePath is the path where CNM state files are stored.
	CNMRuntimePath = ""

	// CNIRuntimePath is the path where CNI state files are stored.
	CNIRuntimePath = ""

	// CNILockPath is the path where CNI lock files are stored.
	CNILockPath = ""

	// CNIStateFilePath is the path to the CNI state file
	CNIStateFilePath = "C:\\k\\azure-vnet.json"

	// CNIIpamStatePath is the name of IPAM state file
	CNIIpamStatePath = "C:\\k\\azure-vnet-ipam.json"

	// CNIBinaryPath is the path to the CNI binary
	CNIBinaryPath = "C:\\k\\azurecni\\bin\\azure-vnet.exe"

	// CNI runtime path on a Kubernetes cluster
	K8SCNIRuntimePath = "C:\\k\\azurecni\\bin"

	// Network configuration file path on a Kubernetes cluster
	K8SNetConfigPath = "C:\\k\\azurecni\\netconf"

	// CNSRuntimePath is the path where CNS state files are stored.
	CNSRuntimePath = ""

	// NPMRuntimePath is the path where NPM state files are stored.
	NPMRuntimePath = ""

	// DNCRuntimePath is the path where DNC state files are stored.
	DNCRuntimePath = ""

	// SDNRemoteArpMacAddress is the registry key for the remote arp mac address.
	// This is set for multitenancy to get arp response from within VM
	// for vlan tagged arp requests
	SDNRemoteArpMacAddress = "12-34-56-78-9a-bc"

	// Command to get SDNRemoteArpMacAddress registry key
	GetSdnRemoteArpMacAddressCommand = "(Get-ItemProperty " +
		"-Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\hns\\State -Name SDNRemoteArpMacAddress).SDNRemoteArpMacAddress"

	// Command to set SDNRemoteArpMacAddress registry key
	SetSdnRemoteArpMacAddressCommand = "Set-ItemProperty " +
		"-Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\hns\\State -Name SDNRemoteArpMacAddress -Value \"12-34-56-78-9a-bc\""

	// Command to restart HNS service
	RestartHnsServiceCommand = "Restart-Service -Name hns"
)

// Flag to check if sdnRemoteArpMacAddress registry key is set
var sdnRemoteArpMacAddressSet = false

// GetOSInfo returns OS version information.
func GetOSInfo() string {
	return "windows"
}

func GetProcessSupport() error {
	cmd := fmt.Sprintf("Get-Process -Id %v", os.Getpid())
	_, err := ExecutePowershellCommand(cmd)
	return err
}

var tickCount = syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount64")

// GetLastRebootTime returns the last time the system rebooted.
func GetLastRebootTime() (time.Time, error) {
	currentTime := time.Now()
	output, _, err := tickCount.Call()
	if errno, ok := err.(syscall.Errno); !ok || errno != 0 {
		log.Printf("Failed to call GetTickCount64, err: %v", err)
		return time.Time{}.UTC(), err
	}
	rebootTime := currentTime.Add(-time.Duration(output) * time.Millisecond).Truncate(time.Second)
	log.Printf("Formatted Boot time: %s", rebootTime.Format(time.RFC3339))
	return rebootTime.UTC(), nil
}

func (p *execClient) ExecuteCommand(command string) (string, error) {
	log.Printf("[Azure-Utils] %s", command)

	var stderr bytes.Buffer
	var out bytes.Buffer
	cmd := exec.Command("cmd", "/c", command)
	cmd.Stderr = &stderr
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("%s:%s", err.Error(), stderr.String())
	}

	return out.String(), nil
}

func SetOutboundSNAT(subnet string) error {
	return nil
}

// ClearNetworkConfiguration clears the azure-vnet.json contents.
// This will be called only when reboot is detected - This is windows specific
func ClearNetworkConfiguration() (bool, error) {
	jsonStore := CNIRuntimePath + "azure-vnet.json"
	log.Printf("Deleting the json store %s", jsonStore)
	cmd := exec.Command("cmd", "/c", "del", jsonStore)

	if err := cmd.Run(); err != nil {
		log.Printf("Error deleting the json store %s", jsonStore)
		return true, err
	}

	return true, nil
}

func KillProcessByName(processName string) {
	p := NewExecClient()
	cmd := fmt.Sprintf("taskkill /IM %v /F", processName)
	p.ExecuteCommand(cmd)
}

// ExecutePowershellCommand executes powershell command
func ExecutePowershellCommand(command string) (string, error) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		return "", fmt.Errorf("Failed to find powershell executable")
	}

	log.Printf("[Azure-Utils] %s", command)

	cmd := exec.Command(ps, command)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("%s:%s", err.Error(), stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

// SetSdnRemoteArpMacAddress sets the regkey for SDNRemoteArpMacAddress needed for multitenancy
func SetSdnRemoteArpMacAddress() error {
	if sdnRemoteArpMacAddressSet == false {
		result, err := ExecutePowershellCommand(GetSdnRemoteArpMacAddressCommand)
		if err != nil {
			return err
		}

		// Set the reg key if not already set or has incorrect value
		if result != SDNRemoteArpMacAddress {
			if _, err = ExecutePowershellCommand(SetSdnRemoteArpMacAddressCommand); err != nil {
				log.Printf("Failed to set SDNRemoteArpMacAddress due to error %s", err.Error())
				return err
			}

			log.Printf("[Azure CNS] SDNRemoteArpMacAddress regKey set successfully. Restarting hns service.")
			if _, err := ExecutePowershellCommand(RestartHnsServiceCommand); err != nil {
				log.Printf("Failed to Restart HNS Service due to error %s", err.Error())
				return err
			}
		}

		sdnRemoteArpMacAddressSet = true
	}

	return nil
}

func GetOSDetails() (map[string]string, error) {
	return nil, nil
}

func GetProcessNameByID(pidstr string) (string, error) {
	pidstr = strings.Trim(pidstr, "\r\n")
	cmd := fmt.Sprintf("Get-Process -Id %s|Format-List", pidstr)
	out, err := ExecutePowershellCommand(cmd)
	if err != nil {
		log.Printf("Process is not running. Output:%v, Error %v", out, err)
		return "", err
	}

	if len(out) <= 0 {
		log.Printf("Output length is 0")
		return "", fmt.Errorf("get-process output length is 0")
	}

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Name") {
			pName := strings.Split(line, ":")
			if len(pName) > 1 {
				return strings.TrimSpace(pName[1]), nil
			}
		}
	}

	return "", fmt.Errorf("Process not found")
}

func PrintDependencyPackageDetails() {
}

// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
func ReplaceFile(source, destination string) error {
	src, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}

	dest, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}

	return windows.MoveFileEx(src, dest, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

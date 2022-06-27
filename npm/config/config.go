package npmconfig

import "github.com/Azure/azure-container-networking/npm/util"

const (
	defaultResyncPeriod    = 15
	defaultListeningPort   = 10091
	defaultGrpcPort        = 10092
	defaultGrpcServicePort = 9002
	// ConfigEnvPath is what's used by viper to load config path
	ConfigEnvPath = "NPM_CONFIG"

	v1 = 1
	v2 = 2
)

// DefaultConfig is the guaranteed configuration NPM can run in out of the box
var DefaultConfig = Config{
	ResyncPeriodInMinutes: defaultResyncPeriod,

	ListeningPort:    defaultListeningPort,
	ListeningAddress: "0.0.0.0",

	Transport: GrpcServerConfig{
		Address:     "0.0.0.0",
		Port:        defaultGrpcPort,
		ServicePort: defaultGrpcServicePort,
	},

	Toggles: Toggles{
		EnablePrometheusMetrics: true,
		EnablePprof:             true,
		EnableHTTPDebugAPI:      true,
		EnableV2NPM:             true,
		PlaceAzureChainFirst:    util.PlaceAzureChainFirst,
		ApplyIPSetsOnNeed:       false,
	},
}

type GrpcServerConfig struct {
	// Address is the address on which the gRPC server will listen
	Address string `json:"Address,omitempty"`
	// Port is the port on which the gRPC server will listen
	Port int `json:"Port,omitempty"`
	// ServicePort is the service port for the client to connect to the gRPC server
	ServicePort int `json:"ServicePort,omitempty"`
}

type Config struct {
	ResyncPeriodInMinutes int              `json:"ResyncPeriodInMinutes,omitempty"`
	ListeningPort         int              `json:"ListeningPort,omitempty"`
	ListeningAddress      string           `json:"ListeningAddress,omitempty"`
	Transport             GrpcServerConfig `json:"Transport,omitempty"`
	Toggles               Toggles          `json:"Toggles,omitempty"`
}

type Toggles struct {
	EnablePrometheusMetrics         bool
	EnablePprof                     bool
	EnableExperimentalEbpfDataplane bool
	EnableHTTPDebugAPI              bool
	EnableV2NPM                     bool
	PlaceAzureChainFirst            bool
	ApplyIPSetsOnNeed               bool
}

type Flags struct {
	KubeConfigPath string `json:"KubeConfigPath"`
	WinEbpf string `json:"WinEbpf`
}

// NPMVersion returns 1 if EnableV2NPM=false and 2 otherwise
func (c Config) NPMVersion() int {
	if c.Toggles.EnableV2NPM {
		return v2
	}
	return v1
}

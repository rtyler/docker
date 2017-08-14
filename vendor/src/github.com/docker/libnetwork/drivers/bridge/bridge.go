package bridge

import (
	"net"
	"sync"

	"github.com/docker/libnetwork/ipallocator"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/options"
	"github.com/docker/libnetwork/portmapper"
	"github.com/docker/libnetwork/types"
)

const (
	networkType             = "bridge"
	vethPrefix              = "veth"
	vethLen                 = 7
	containerVethPrefix     = "eth"
	maxAllocatePortAttempts = 10
	ifaceID                 = 1
)

var (
	ipAllocator *ipallocator.IPAllocator
)

// configuration info for the "bridge" driver.
type configuration struct {
	EnableIPForwarding bool
}

// networkConfiguration for network specific configuration
type networkConfiguration struct {
	BridgeName            string
	AddressIPv4           *net.IPNet
	FixedCIDR             *net.IPNet
	FixedCIDRv6           *net.IPNet
	EnableIPv6            bool
	EnableIPTables        bool
	EnableIPMasquerade    bool
	EnableICC             bool
	Mtu                   int
	DefaultGatewayIPv4    net.IP
	DefaultGatewayIPv6    net.IP
	DefaultBindingIP      net.IP
	AllowNonDefaultBridge bool
	EnableUserlandProxy   bool
}

// endpointConfiguration represents the user specified configuration for the sandbox endpoint
type endpointConfiguration struct {
	MacAddress   net.HardwareAddr
	PortBindings []types.PortBinding
	ExposedPorts []types.TransportPort
}

// containerConfiguration represents the user specified configuration for a container
type containerConfiguration struct {
	ParentEndpoints []string
	ChildEndpoints  []string
}

type bridgeEndpoint struct {
	id              types.UUID
	srcName         string
	addr            *net.IPNet
	addrv6          *net.IPNet
	macAddress      net.HardwareAddr
	config          *endpointConfiguration // User specified parameters
	containerConfig *containerConfiguration
	portMapping     []types.PortBinding // Operation port bindings
}

// Interface models the bridge network device.
type bridgeInterface struct {
    // FREEBSD
	//Link        netlink.Link
	bridgeIPv4  *net.IPNet
	bridgeIPv6  *net.IPNet
	gatewayIPv4 net.IP
	gatewayIPv6 net.IP
}

type bridgeNetwork struct {
	id         types.UUID
	bridge     *bridgeInterface // The bridge's L3 interface
	config     *networkConfiguration
	endpoints  map[types.UUID]*bridgeEndpoint // key: endpoint id
	portMapper *portmapper.PortMapper
	sync.Mutex
}

type driver struct {
	config   *configuration
	network  *bridgeNetwork
	networks map[types.UUID]*bridgeNetwork
	sync.Mutex
}

func init() {
	ipAllocator = ipallocator.New()
}

func (d *driver) Config(option map[string]interface{}) error {
	var config *configuration

	d.Lock()
	defer d.Unlock()

	if d.config != nil {
		return &ErrConfigExists{}
	}

	genericData, ok := option[netlabel.GenericData]
	if ok && genericData != nil {
		switch opt := genericData.(type) {
		case options.Generic:
			opaqueConfig, err := options.GenerateFromModel(opt, &configuration{})
			if err != nil {
				return err
			}
			config = opaqueConfig.(*configuration)
		case *configuration:
			config = opt
		default:
			return &ErrInvalidDriverConfig{}
		}

		d.config = config
	} else {
		config = &configuration{}
	}

	if config.EnableIPForwarding {
		return setupIPForwarding(config)
	}

	return nil
}

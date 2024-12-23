package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/grepplabs/kafka-proxy/config"
	"github.com/grepplabs/kafka-proxy/pkg/libs/util"
	"github.com/sirupsen/logrus"
)

// Creates a listener from a listener config
type ListenFunc func(cfg config.ListenerConfig) (l net.Listener, err error)

type Listeners struct {
	// Source of new connections to Kafka broker.
	connSrc chan Conn
	// listen IP for dynamically start
	defaultListenerIP string
	// advertised address for dynamic listeners
	dynamicAdvertisedListener string
	// socket TCP options
	tcpConnOptions TCPConnOptions

	listenFunc ListenFunc

	deterministicListeners   bool
	disableDynamicListeners  bool
	dynamicSequentialMinPort int

	// upsteam (backend) to local listener mapping
	brokerToListenerConfig   map[string]config.ListenerConfig
	brokerIdToListenerConfig map[int32]config.ListenerConfig
	lock                     sync.RWMutex
}

func NewListeners(cfg *config.Config) (*Listeners, error) {

	defaultListenerIP := cfg.Proxy.DefaultListenerIP
	dynamicAdvertisedListener := cfg.Proxy.DynamicAdvertisedListener

	tcpConnOptions := TCPConnOptions{
		KeepAlive:       cfg.Proxy.ListenerKeepAlive,
		ReadBufferSize:  cfg.Proxy.ListenerReadBufferSize,
		WriteBufferSize: cfg.Proxy.ListenerWriteBufferSize,
	}

	var tlsConfig *tls.Config
	if cfg.Proxy.TLS.Enable {
		var err error
		tlsConfig, err = newTLSListenerConfig(cfg)
		if err != nil {
			return nil, err
		}
	}

	listenFunc := func(cfg config.ListenerConfig) (net.Listener, error) {
		if tlsConfig != nil {
			return tls.Listen("tcp", cfg.ListenerAddress, tlsConfig)
		}
		return net.Listen("tcp", cfg.ListenerAddress)
	}

	brokerToListenerConfig, err := getBrokerToListenerConfig(cfg)
	if err != nil {
		return nil, err
	}

	brokerIdToListenerConfig := make(map[int32]config.ListenerConfig)

	return &Listeners{
		defaultListenerIP:         defaultListenerIP,
		dynamicAdvertisedListener: dynamicAdvertisedListener,
		connSrc:                   make(chan Conn, 1),
		brokerToListenerConfig:    brokerToListenerConfig,
		brokerIdToListenerConfig:  brokerIdToListenerConfig,
		tcpConnOptions:            tcpConnOptions,
		listenFunc:                listenFunc,
		deterministicListeners:    cfg.Proxy.DeterministicListeners,
		disableDynamicListeners:   cfg.Proxy.DisableDynamicListeners,
		dynamicSequentialMinPort:  cfg.Proxy.DynamicSequentialMinPort,
	}, nil
}

func getBrokerToListenerConfig(cfg *config.Config) (map[string]config.ListenerConfig, error) {
	brokerToListenerConfig := make(map[string]config.ListenerConfig)

	for _, v := range cfg.Proxy.BootstrapServers {
		if lc, ok := brokerToListenerConfig[v.BrokerAddress]; ok {
			if lc.ListenerAddress != v.ListenerAddress || lc.AdvertisedAddress != v.AdvertisedAddress {
				return nil, fmt.Errorf("bootstrap server mapping %s configured twice: %v and %v", v.BrokerAddress, v, lc)
			}
			continue
		}
		logrus.Infof("Bootstrap server %s advertised as %s", v.BrokerAddress, v.AdvertisedAddress)
		brokerToListenerConfig[v.BrokerAddress] = v
	}

	externalToListenerConfig := make(map[string]config.ListenerConfig)
	for _, v := range cfg.Proxy.ExternalServers {
		if lc, ok := externalToListenerConfig[v.BrokerAddress]; ok {
			if lc.ListenerAddress != v.ListenerAddress {
				return nil, fmt.Errorf("external server mapping %s configured twice: %s and %v", v.BrokerAddress, v.ListenerAddress, lc)
			}
			continue
		}
		if v.ListenerAddress != v.AdvertisedAddress {
			return nil, fmt.Errorf("external server mapping has different listener and advertised addresses %v", v)
		}
		externalToListenerConfig[v.BrokerAddress] = v
	}

	for _, v := range externalToListenerConfig {
		if lc, ok := brokerToListenerConfig[v.BrokerAddress]; ok {
			if lc.AdvertisedAddress != v.AdvertisedAddress {
				return nil, fmt.Errorf("bootstrap and external server mappings %s with different advertised addresses: %v and %v", v.BrokerAddress, v.ListenerAddress, lc.AdvertisedAddress)
			}
			continue
		}
		logrus.Infof("External server %s advertised as %s", v.BrokerAddress, v.AdvertisedAddress)
		brokerToListenerConfig[v.BrokerAddress] = v
	}
	return brokerToListenerConfig, nil
}

// func getIdtoListenerConfig(cfg *config.Config)

// netAddressMappingFunc
func (p *Listeners) GetNetAddressMapping(brokerHost string, brokerPort int32, brokerId int32) (listenerHost string, listenerPort int32, err error) {
	fmt.Println("called GetNetAddressMapping")
	fmt.Println("brokerId:" + fmt.Sprint(brokerId))

	if brokerHost == "" || brokerPort <= 0 {
		return "", 0, fmt.Errorf("broker address '%s:%d' is invalid", brokerHost, brokerPort)
	}

	brokerAddress := net.JoinHostPort(brokerHost, fmt.Sprint(brokerPort))

	// old behavior: take upstream from metadata, look up mapping (maps upstream to local listener, including advertised)
	// if mapping exists, continue
	// if mapping doesn't exist, create new listener (and add to mapping)

	// fmt.Println("Lookup using net.JoinHostPort")
	// fmt.Println(brokerPort)
	// fmt.Println(brokerAddress)

	// var listenerConfig config.ListenerConfig

	// Scenarios:
	// look up by broker id -> get listenerConfig
	// 	look up by upstream listener -> get listenerConfig
	// if brokerId found, and two listenerconfigs match, do nothing
	// if brokerId found, and listenerConfigs don't match

	// //////////////
	// Logic:
	// * if deterministic:
	// * look up by broker ID
	// * if broker ID found, and same, do nothing
	// * If broker id found, and not same, delete, start new listener
	// * if broker id not found
	// * start new listebrokerAddress
	// * otherwise, if not deterministic, follow old logic
	// //////////////
	// if using deterministic listeners, first look up by broker id
	// if p.deterministicListeners {
	// 	listenerConfig, brokerFound
	// }
	// if !p.disableDynamicListeners
	// idListenerConfig, brokerIdFound := p.brokerIdToListenerConfig[brokerId]

	// focus on readability vs. DRY

	// thesis: right now we're looking at dropping existing listeners and starting new ones
	// we probably don't actually want to stop the listener; we just want to redirect
	// need to figure out where the upstreams are held

	// if p.deterministicListeners {
	// 	p.lock.RLock()
	// 	// listenerConfig, found := p.brokerIdToListenerConfig[brokerId]
	// 	p.lock.RUnlock()

	// type ListenerConfig struct {
	// 	BrokerAddress     string
	// 	ListenerAddress   string
	// 	AdvertisedAddress string
	// 	Listener          net.Listener
	// }

	// 	// LC looks like this
	// 	// upstream local advertised
	// ip-10-32-1-28.ap-southeast-1.compute.internal:20040 ->
	// 	// {ip-10-32-1-28.ap-southeast-1.compute.internal:20040 0.0.0.0:40030 ip-10-32-1-28.ap-southeast-1.compute.internal:40030 0xc000129ac0}
	// 	// if found {
	// 	// 	if upstream matches
	// 	// 	if upstream doesn't match
	// 	// } else {
	// 	// start new listener
	// 	// }

	// }
	p.lock.RLock()
	listenerConfig, ok := p.brokerToListenerConfig[brokerAddress]
	p.lock.RUnlock()

	fmt.Println(brokerAddress)
	fmt.Println("maps to")
	fmt.Println(listenerConfig)
	fmt.Println(ok)

	if ok {
		logrus.Infof("Address mappings broker=%s, listener=%s, advertised=%s", listenerConfig.BrokerAddress, listenerConfig.ListenerAddress, listenerConfig.AdvertisedAddress)
		return util.SplitHostPort(listenerConfig.AdvertisedAddress)
	}
	if !p.disableDynamicListeners {
		logrus.Infof("Starting dynamic listener for broker %s", brokerAddress)
		// ListenDynamicInstance also starts the listener
		return p.ListenDynamicInstance(brokerAddress, brokerId)
	}
	return "", 0, fmt.Errorf("net address mapping for %s:%d was not found", brokerHost, brokerPort)
}

func (p *Listeners) ListenDynamicInstance(brokerAddress string, brokerId int32) (string, int32, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	// double check
	if v, ok := p.brokerToListenerConfig[brokerAddress]; ok {
		return util.SplitHostPort(v.AdvertisedAddress)
	}

	var defaultListenerAddress string

	if p.deterministicListeners {
		defaultListenerAddress = net.JoinHostPort(p.defaultListenerIP, fmt.Sprint(p.dynamicSequentialMinPort+int(brokerId)))
	} else {
		defaultListenerAddress = net.JoinHostPort(p.defaultListenerIP, fmt.Sprint(p.dynamicSequentialMinPort))
		if p.dynamicSequentialMinPort != 0 {
			p.dynamicSequentialMinPort += 1
		}
	}

	cfg := config.ListenerConfig{ListenerAddress: defaultListenerAddress, BrokerAddress: brokerAddress}
	// This is where the actual 'listen' happen
	listener, err := listenInstance(p.connSrc, cfg, p.tcpConnOptions, p.listenFunc)
	if err != nil {
		return "", 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	address := net.JoinHostPort(p.defaultListenerIP, fmt.Sprint(port))

	dynamicAdvertisedListener := p.dynamicAdvertisedListener
	if dynamicAdvertisedListener == "" {
		dynamicAdvertisedListener = p.defaultListenerIP
	}

	advertisedAddress := net.JoinHostPort(dynamicAdvertisedListener, fmt.Sprint(port))
	p.brokerToListenerConfig[brokerAddress] = config.ListenerConfig{BrokerAddress: brokerAddress, ListenerAddress: address, AdvertisedAddress: advertisedAddress, Listener: listener}
	p.brokerIdToListenerConfig[brokerId] = p.brokerToListenerConfig[brokerAddress]
	fmt.Println(p.brokerToListenerConfig[brokerAddress])

	logrus.Infof("Dynamic listener %s for broker %s advertised as %s", address, brokerAddress, advertisedAddress)

	return dynamicAdvertisedListener, int32(port), nil
}

func (p *Listeners) ListenInstances(cfgs []config.ListenerConfig) (<-chan Conn, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	// allows multiple local addresses to point to the remote
	for _, v := range cfgs {
		_, err := listenInstance(p.connSrc, v, p.tcpConnOptions, p.listenFunc)
		if err != nil {
			return nil, err
		}
	}
	return p.connSrc, nil
}

// listenFunc is just net.listen or tls.listen (with tls config)
func listenInstance(dst chan<- Conn, cfg config.ListenerConfig, opts TCPConnOptions, listenFunc ListenFunc) (net.Listener, error) {
	l, err := listenFunc(cfg)
	if err != nil {
		return nil, err
	}
	go withRecover(func() {
		for {
			c, err := l.Accept()
			if err != nil {
				logrus.Infof("Error in accept for %q on %v: %v", cfg, cfg.ListenerAddress, err)
				l.Close()
				return
			}
			if tcpConn, ok := c.(*net.TCPConn); ok {
				if err := opts.setTCPConnOptions(tcpConn); err != nil {
					logrus.Infof("WARNING: Error while setting TCP options for accepted connection %q on %v: %v", cfg, l.Addr().String(), err)
				}
			}
			logrus.Infof("New connection for %s", cfg.BrokerAddress)
			dst <- Conn{BrokerAddress: cfg.BrokerAddress, LocalConnection: c}
		}
	})

	logrus.Infof("Listening on %s (%s) for remote %s", cfg.ListenerAddress, l.Addr().String(), cfg.BrokerAddress)
	return l, nil
}

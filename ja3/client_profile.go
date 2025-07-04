package ja3

import (
	"github.com/smallerqiu/ja3-client/http2"
	tls "github.com/smallerqiu/utls"
)

type ClientProfile struct {
	ClientHelloId     tls.ClientHelloID
	HeaderPriority    *http2.PriorityParam
	Settings          map[http2.SettingID]uint32
	Priorities        []http2.Priority
	PseudoHeaderOrder []string
	SettingsOrder     []http2.SettingID
	ConnectionFlow    uint32
}

func NewClientProfile(clientHelloId tls.ClientHelloID, settings map[http2.SettingID]uint32, settingsOrder []http2.SettingID, pseudoHeaderOrder []string, connectionFlow uint32, priorities []http2.Priority, headerPriority *http2.PriorityParam) ClientProfile {
	return ClientProfile{
		ClientHelloId:     clientHelloId,
		Settings:          settings,
		SettingsOrder:     settingsOrder,
		PseudoHeaderOrder: pseudoHeaderOrder,
		ConnectionFlow:    connectionFlow,
		Priorities:        priorities,
		HeaderPriority:    headerPriority,
	}
}
func (c ClientProfile) GetClientHelloSpec() (tls.ClientHelloSpec, error) {
	return c.ClientHelloId.ToSpec()
}

func (c ClientProfile) GetClientHelloStr() string {
	return c.ClientHelloId.Str()
}

func (c ClientProfile) GetSettings() map[http2.SettingID]uint32 {
	return c.Settings
}

func (c ClientProfile) GetSettingsOrder() []http2.SettingID {
	return c.SettingsOrder
}

func (c ClientProfile) GetConnectionFlow() uint32 {
	return c.ConnectionFlow
}

func (c ClientProfile) GetPseudoHeaderOrder() []string {
	return c.PseudoHeaderOrder
}

func (c ClientProfile) GetHeaderPriority() *http2.PriorityParam {
	return c.HeaderPriority
}

func (c ClientProfile) GetClientHelloId() tls.ClientHelloID {
	return c.ClientHelloId
}

func (c ClientProfile) GetPriorities() []http2.Priority {
	return c.Priorities
}

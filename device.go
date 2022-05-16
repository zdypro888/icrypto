package icrypto

type OSEnum int

// String string
func (os OSEnum) String() string {
	if os == OSiOS {
		return "iPhone OS"
	}
	if os == OSmacOS {
		return "Mac OS X"
	}
	return ""
}

const (
	OSmacOS OSEnum = 1
	OSiOS   OSEnum = 2
)

type MacOS struct {
	Model         string `plist:"Model,omitempty" bson:"Model,omitempty" json:"Model,omitempty"`
	OSRevision    uint64 `plist:"OS-Revision,omitempty" bson:"OSRevision,omitempty" json:"OSRevision,omitempty"`
	OSVersion     string `plist:"OS-Version,omitempty" bson:"OSVersion,omitempty" json:"OSVersion,omitempty"`
	BoardID       string `plist:"Board-id,omitempty" bson:"BoardId,omitempty" json:"BoardId,omitempty"`
	DiskUUID      string `plist:"Disk UUID,omitempty" bson:"DiskId,omitempty" json:"DiskId,omitempty"`
	HardWareUUID  string `plist:"Hardware UUID,omitempty" bson:"HWID,omitempty" json:"HardWareUUID,omitempty"`
	MacAddress    []byte `plist:"Mac-Address,omitempty" bson:"MacAddress,omitempty" json:"MacAddress,omitempty"`
	NvramROM      []byte `plist:"ROM,omitempty" bson:"ROM,omitempty" json:"ROM,omitempty"`
	NvramMLB      string `plist:"BoardSerialNumber,omitempty" bson:"MLB,omitempty" json:"MLB,omitempty"`
	KGq3489ugfi   []byte `plist:"KGq3489ugfi,omitempty" bson:"KGq3489ugfi,omitempty" json:"KGq3489ugfi,omitempty"`
	KFyp98tpgj    []byte `plist:"KFyp98tpgj,omitempty" bson:"KFyp98tpgj,omitempty" json:"KFyp98tpgj,omitempty"`
	KkbjfrfpoJU   []byte `plist:"KkbjfrfpoJU,omitempty" bson:"KkbjfrfpoJU,omitempty" json:"KkbjfrfpoJU,omitempty"`
	KoycqAZloTNDm []byte `plist:"KoycqAZloTNDm,omitempty" bson:"KoycqAZloTNDm,omitempty" json:"KoycqAZloTNDm,omitempty"`
	KabKPld1EcMni []byte `plist:"KabKPld1EcMni,omitempty" bson:"KabKPld1EcMni,omitempty" json:"KabKPld1EcMni,omitempty"`
}

type IOS struct {
	ProductType                           string `plist:"ProductType" bson:"ProductType" json:"ProductType"`
	UniqueChipID                          uint64 `plist:"UniqueChipID" bson:"UniqueChipID,omitempty" json:"UniqueChipID,omitempty"`
	UniqueDeviceID                        string `plist:"UniqueDeviceID" bson:"UniqueDeviceID,omitempty" json:"UniqueDeviceID,omitempty"`
	ModelNumber                           string `plist:"ModelNumber" bson:"ModelNumber,omitempty" json:"ModelNumber,omitempty"`
	WifiAddress                           string `plist:"WifiAddress,omitempty" bson:"WifiAddress,omitempty" json:"WifiAddress,omitempty"`
	InternationalMobileEquipmentIdentity  string `plist:"InternationalMobileEquipmentIdentity" bson:"InternationalMobileEquipmentIdentity,omitempty" json:"InternationalMobileEquipmentIdentity,omitempty"`
	MobileEquipmentIdentifier             string `plist:"MobileEquipmentIdentifier" bson:"MobileEquipmentIdentifier,omitempty" json:"MobileEquipmentIdentifier,omitempty"`
	IntegratedCircuitCardIdentity         string `plist:"IntegratedCircuitCardIdentity" bson:"IntegratedCircuitCardIdentity,omitempty" json:"IntegratedCircuitCardIdentity,omitempty"`
	InternationalMobileSubscriberIdentity string `plist:"InternationalMobileSubscriberIdentity" bson:"InternationalMobileSubscriberIdentity,omitempty" json:"InternationalMobileSubscriberIdentity,omitempty"`
	BluetoothAddress                      string `plist:"BluetoothAddress,omitempty" bson:"BluetoothAddress,omitempty" json:"BluetoothAddress,omitempty"`
	ActivationInfo                        []byte `plist:"ActivationInfo,omitempty" bson:"ActivationInfo,omitempty" json:"ActivationInfo,omitempty"`
}

type Device struct {
	OSType           OSEnum `plist:"OSType" bson:"OSType" json:"OSType"`
	SerialNumber     string `plist:"SerialNumber" bson:"SerialNumber" json:"SerialNumber"`
	MacOS            `plist:",inline" bson:",inline" json:",inline"`
	IOS              `plist:",inline" bson:",inline" json:",inline"`
	BuildVersion     string `plist:"BuildVersion" bson:"BuildVersion,omitempty" json:"BuildVersion,omitempty"`
	ProductVersion   string `plist:"ProductVersion" bson:"ProductVersion,omitempty" json:"ProductVersion,omitempty"`
	ClientIdentifier string `plist:"AppleIDClientIdentifier,omitempty" bson:"AppleIDClientIdentifier,omitempty" json:"AppleIDClientIdentifier,omitempty"`
	PrivateKey       []byte `plist:"PrivateKey,omitempty" bson:"PrivateKey,omitempty" json:"PrivateKey,omitempty"`
	Certificate      []byte `plist:"Certificate,omitempty" bson:"Certificate,omitempty" json:"Certificate,omitempty"`
	FairplayKeyData  []byte `plist:"FairplayKeyData,omitempty" bson:"FairplayKeyData,omitempty" json:"FairplayKeyData,omitempty"`
	PushToken        []byte `plist:"PushToken,omitempty" bson:"PushToken,omitempty" json:"PushToken,omitempty"`
	ADI              []byte `plist:"ADI,omitempty" bson:"ADI,omitempty" json:"ADI,omitempty"`
	ADID             string `plist:"ADID,omitempty" bson:"ADID,omitempty" json:"ADID,omitempty"`
	RINFO            int64  `plist:"RINFO,omitempty" bson:"RINFO,omitempty" json:"RINFO,omitempty"`

	AcceptLanguage   string `plist:"AcceptLanguage,omitempty" bson:"AcceptLanguage,omitempty" json:"AcceptLanguage,omitempty"`
	ApppleILocale    string `plist:"ApppleILocale,omitempty" bson:"ApppleILocale,omitempty" json:"ApppleILocale,omitempty"`
	XMMeCountry      string `plist:"XMMeCountry,omitempty" bson:"XMMeCountry,omitempty" json:"XMMeCountry,omitempty"`
	CFNetworkVersion string `plist:"CFNetworkVersion,omitempty" bson:"CFNetworkVersion,omitempty" json:"CFNetworkVersion,omitempty"`
	DarwinVersion    string `plist:"DarwinVersion,omitempty" bson:"DarwinVersion,omitempty" json:"DarwinVersion,omitempty"`
}

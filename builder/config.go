package builder

type Config struct {
	Enabled                       bool     `toml:",omitempty"`
	EnableValidatorChecks         bool     `toml:",omitempty"`
	EnableLocalRelay              bool     `toml:",omitempty"`
	SlotsInEpoch                  uint64   `toml:",omitempty"`
	SecondsInSlot                 uint64   `toml:",omitempty"`
	DisableBundleFetcher          bool     `toml:",omitempty"`
	DryRun                        bool     `toml:",omitempty"`
	BuilderSecretKey              string   `toml:",omitempty"`
	RelaySecretKey                string   `toml:",omitempty"`
	ListenAddr                    string   `toml:",omitempty"`
	GenesisForkVersion            string   `toml:",omitempty"`
	BellatrixForkVersion          string   `toml:",omitempty"`
	GenesisValidatorsRoot         string   `toml:",omitempty"`
	BeaconEndpoints               []string `toml:",omitempty"`
	RemoteRelayEndpoint           string   `toml:",omitempty"`
	SecondaryRemoteRelayEndpoints []string `toml:",omitempty"`
	ValidationBlocklist           string   `toml:",omitempty"`
}

// DefaultConfig is the default config for the builder.
var DefaultConfig = Config{
	Enabled:                       false,
	EnableValidatorChecks:         false,
	EnableLocalRelay:              false,
	SlotsInEpoch:                  32,
	SecondsInSlot:                 12,
	DisableBundleFetcher:          false,
	DryRun:                        false,
	BuilderSecretKey:              "0x2fc12ae741f29701f8e30f5de6350766c020cb80768a0ff01e6838ffd2431e11",
	RelaySecretKey:                "0x2fc12ae741f29701f8e30f5de6350766c020cb80768a0ff01e6838ffd2431e11",
	ListenAddr:                    ":28545",
	GenesisForkVersion:            "0x00000000",
	BellatrixForkVersion:          "0x02000000",
	GenesisValidatorsRoot:         "0x0000000000000000000000000000000000000000000000000000000000000000",
	BeaconEndpoints:               []string{"http://127.0.0.1:5052"},
	RemoteRelayEndpoint:           "",
	SecondaryRemoteRelayEndpoints: nil,
	ValidationBlocklist:           "",
}

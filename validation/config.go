package validation

type Config struct {
	Enabled            bool   `toml:",omitempty"`
	ListenAddr         string `toml:",omitempty"`
	Blocklist          string `toml:",omitempty"`
	UseCoinbaseDiff    bool   `toml:",omitempty"`
	ExcludeWithdrawals bool   `toml:",omitempty"`
}

// DefaultConfig is the default config for validation api.
var DefaultConfig = Config{
	Enabled:            false,
	ListenAddr:         ":28546",
	Blocklist:          "",
	UseCoinbaseDiff:    false,
	ExcludeWithdrawals: false,
}

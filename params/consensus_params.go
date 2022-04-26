package params

import (
	"os"
)

var (
	TribeReadyForAcceptTxs = make(chan struct{})
	InitTribe              = make(chan struct{})
)

func GetIPCPath() string {
	return os.Getenv("IPCPATH")
}

func IsTestnet() bool {
	return os.Getenv("TESTNET") == "1"
}

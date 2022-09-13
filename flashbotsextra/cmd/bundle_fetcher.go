package main

import (
	"os"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
)

func main() {
	// Test bundle fetcher
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))
	mevBundleCh := make(chan []types.MevBundle)
	blockNumCh := make(chan int64)
	db, err := flashbotsextra.NewDatabaseService("postgres://postgres:postgres@localhost:5432/test?sslmode=disable")
	if err != nil {
		panic(err)
	}
	bundleFetcher := flashbotsextra.NewBundleFetcher(nil, db, blockNumCh, mevBundleCh, false)

	go bundleFetcher.Run()
	log.Info("waiting for mev bundles")
	go func() {
		blockNum := []int64{15232009, 15232008, 15232010}
		for _, num := range blockNum {
			<-time.After(time.Second)
			blockNumCh <- num
		}
	}()
	for bundles := range mevBundleCh {
		for _, bundle := range bundles {
			log.Info("bundle info", "blockNum", bundle.BlockNumber, "txsLength", len(bundle.Txs))
		}
	}
}

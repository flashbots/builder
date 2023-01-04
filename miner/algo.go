package miner

type BundleAlgo interface {
	BuildBlock(order []Order) (*environment, []Order) // returns the bundles used in the block to save to db
}

type GreedyAlgo struct {
	inputEnvironment *environment
	chainData        chainData
	interrupt        *int32
}

func (g *GreedyAlgo) BuildBlock(orders []Order) (*environment, []Order) {
	// ...
	return nil, nil
}

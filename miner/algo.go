package miner

type BundleAlgo interface {
	MergeOrders(orders []Order) (*environment, []Order) // returns the bundles used in the block to save to db
}

func BuildBlock(orders []Order, algo BundleAlgo) (*environment, []Order) {
	// metrics
	newEnv, committedOrders := algo.MergeOrders(orders)
	// metrics
	return newEnv, committedOrders
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

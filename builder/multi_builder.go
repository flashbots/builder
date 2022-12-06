package builder

import (
	"errors"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

type MultiBuilder struct {
	Instances []IBuilder
}

func (m MultiBuilder) Collapse() IBuilder {
	if len(m.Instances) == 1 {
		return m.Instances[0]
	}
	return m
}

func (m MultiBuilder) OnPayloadAttribute(attrs *types.BuilderPayloadAttributes) error {
	for _, instance := range m.Instances {
		go instance.OnPayloadAttribute(attrs)
	}

	return nil
}

func (m MultiBuilder) Start() error {
	for _, instance := range m.Instances {
		err := instance.Start()
		if err != nil {
			return err
		}
	}

	return nil
}

func (m MultiBuilder) Stop() error {
	var anyError bool = false // TODO: move to multierror
	for _, instance := range m.Instances {
		err := instance.Stop()
		if err != nil {
			log.Error("could not stop builder instance", "instance", instance, "err", err)
			anyError = true
		}
	}

	if anyError {
		return errors.New("could not stop one or more of the builder instances")
	}

	return nil
}

package service

import (
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
)

type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// EventFactory owns creation of canonical, redacted Audit events. Application
// services orchestrate it; persistence receives only prepared events.
type EventFactory struct{ clock Clock }

func NewEventFactory(clock Clock) *EventFactory {
	if clock == nil {
		clock = systemClock{}
	}
	return &EventFactory{clock: clock}
}

func (f *EventFactory) Build(request contract.AppendRequest) (contract.Event, error) {
	return contract.BuildEvent(request, f.clock.Now())
}

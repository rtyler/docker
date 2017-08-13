package daemon

import (
	"bufio"
	"sync"
	"time"

	"github.com/docker/docker/pkg/pubsub"
	"github.com/opencontainers/runc/libcontainer/system"
)

// newStatsCollector returns a new statsCollector that collections
// network and cgroup stats for a registered container at the specified
// interval.  The collector allows non-running containers to be added
// and will start processing stats when they are started.
func newStatsCollector(interval time.Duration) *statsCollector {
	s := &statsCollector{
		interval:   interval,
		publishers: make(map[*Container]*pubsub.Publisher),
		clockTicks: uint64(system.GetClockTicks()),
		bufReader:  bufio.NewReaderSize(nil, 128),
	}
	go s.run()
	return s
}

// statsCollector manages and provides container resource stats
type statsCollector struct {
	m          sync.Mutex
	interval   time.Duration
	clockTicks uint64
	publishers map[*Container]*pubsub.Publisher
	bufReader  *bufio.Reader
}

// collect registers the container with the collector and adds it to
// the event loop for collection on the specified interval returning
// a channel for the subscriber to receive on.
func (s *statsCollector) collect(c *Container) chan interface{} {
	return nil
}

// stopCollection closes the channels for all subscribers and removes
// the container from metrics collection.
func (s *statsCollector) stopCollection(c *Container) {
}

// unsubscribe removes a specific subscriber from receiving updates for a container's stats.
func (s *statsCollector) unsubscribe(c *Container, ch chan interface{}) {
}

func (s *statsCollector) run() {
}

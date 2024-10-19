package events

type EventType int

const (
	GENERAL EventType = iota
	NOTICE
	ERROR
)

type Event struct {
	Type    EventType
	Code    int
	Message string
}

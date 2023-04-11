// Code generated by \"eventhandlers\"; DO NOT EDIT
// See events.go

package JuhGn9d5PBgMerWRbcSPYxSf

// Following are all the event types.
// Event type values are used to match the events returned by Discord.
// EventTypes surrounded by __ are synthetic and are internal to DiscordGo.
const (
	connectEventType                             = "__CONNECT__"
	disconnectEventType                          = "__DISCONNECT__"
	messageCreateEventType                       = "MESSAGE_CREATE"
	messageUpdateEventType                       = "MESSAGE_UPDATE"
	rateLimitEventType                           = "__RATE_LIMIT__"
	readyEventType                               = "READY"
	resumedEventType                             = "RESUMED"
)

// connectEventHandler is an event handler for Connect events.
type connectEventHandler func(*Session, *Connect)

// Type returns the event type for Connect events.
func (eh connectEventHandler) Type() string {
	return connectEventType
}

// Handle is the handler for Connect events.
func (eh connectEventHandler) Handle(s *Session, i interface{}) {
	if t, ok := i.(*Connect); ok {
		eh(s, t)
	}
}

// disconnectEventHandler is an event handler for Disconnect events.
type disconnectEventHandler func(*Session, *Disconnect)

// Type returns the event type for Disconnect events.
func (eh disconnectEventHandler) Type() string {
	return disconnectEventType
}

// Handle is the handler for Disconnect events.
func (eh disconnectEventHandler) Handle(s *Session, i interface{}) {
	if t, ok := i.(*Disconnect); ok {
		eh(s, t)
	}
}

// messageCreateEventHandler is an event handler for MessageCreate events.
type messageCreateEventHandler func(*Session, *MessageCreate)

// Type returns the event type for MessageCreate events.
func (eh messageCreateEventHandler) Type() string {
	return messageCreateEventType
}

// New returns a new instance of MessageCreate.
func (eh messageCreateEventHandler) New() interface{} {
	return &MessageCreate{}
}

// Handle is the handler for MessageCreate events.
func (eh messageCreateEventHandler) Handle(s *Session, i interface{}) {
	if t, ok := i.(*MessageCreate); ok {
		eh(s, t)
	}
}

// messageUpdateEventHandler is an event handler for MessageUpdate events.
type messageUpdateEventHandler func(*Session, *MessageUpdate)

// Type returns the event type for MessageUpdate events.
func (eh messageUpdateEventHandler) Type() string {
	return messageUpdateEventType
}

// New returns a new instance of MessageUpdate.
func (eh messageUpdateEventHandler) New() interface{} {
	return &MessageUpdate{}
}

// Handle is the handler for MessageUpdate events.
func (eh messageUpdateEventHandler) Handle(s *Session, i interface{}) {
	if t, ok := i.(*MessageUpdate); ok {
		eh(s, t)
	}
}

// rateLimitEventHandler is an event handler for RateLimit events.
type rateLimitEventHandler func(*Session, *RateLimit)

// Type returns the event type for RateLimit events.
func (eh rateLimitEventHandler) Type() string {
	return rateLimitEventType
}

// Handle is the handler for RateLimit events.
func (eh rateLimitEventHandler) Handle(s *Session, i interface{}) {
	if t, ok := i.(*RateLimit); ok {
		eh(s, t)
	}
}

// readyEventHandler is an event handler for Ready events.
type readyEventHandler func(*Session, *Ready)

// Type returns the event type for Ready events.
func (eh readyEventHandler) Type() string {
	return readyEventType
}

// New returns a new instance of Ready.
func (eh readyEventHandler) New() interface{} {
	return &Ready{}
}

// Handle is the handler for Ready events.
func (eh readyEventHandler) Handle(s *Session, i interface{}) {
	if t, ok := i.(*Ready); ok {
		eh(s, t)
	}
}

// resumedEventHandler is an event handler for Resumed events.
type resumedEventHandler func(*Session, *Resumed)

// Type returns the event type for Resumed events.
func (eh resumedEventHandler) Type() string {
	return resumedEventType
}

// New returns a new instance of Resumed.
func (eh resumedEventHandler) New() interface{} {
	return &Resumed{}
}

// Handle is the handler for Resumed events.
func (eh resumedEventHandler) Handle(s *Session, i interface{}) {
	if t, ok := i.(*Resumed); ok {
		eh(s, t)
	}
}

func handlerForInterface(handler interface{}) EventHandler {
	switch v := handler.(type) {
	case func(*Session, interface{}):
		return interfaceEventHandler(v)
	case func(*Session, *Connect):
		return connectEventHandler(v)
	case func(*Session, *Disconnect):
		return disconnectEventHandler(v)
	case func(*Session, *MessageCreate):
		return messageCreateEventHandler(v)
	case func(*Session, *MessageUpdate):
		return messageUpdateEventHandler(v)
	case func(*Session, *RateLimit):
		return rateLimitEventHandler(v)
	case func(*Session, *Ready):
		return readyEventHandler(v)
	case func(*Session, *Resumed):
		return resumedEventHandler(v)
	}

	return nil
}

func init() {
	registerInterfaceProvider(messageCreateEventHandler(nil))
	registerInterfaceProvider(messageUpdateEventHandler(nil))
	registerInterfaceProvider(readyEventHandler(nil))
	registerInterfaceProvider(resumedEventHandler(nil))
}
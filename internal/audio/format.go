package audio

// ChannelCount represents the number of audio channels.
type ChannelCount int

// Channel configurations.
const (
	// Mono represents single-channel audio.
	Mono ChannelCount = 1
	// Stereo represents dual-channel audio.
	Stereo ChannelCount = 2
)

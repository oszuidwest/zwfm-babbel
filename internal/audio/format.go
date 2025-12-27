package audio

// SampleRate represents audio sample rate in Hz
type SampleRate int

// Sample rates for audio processing.
const (
	// SampleRate44100 represents CD-quality audio at 44.1 kHz
	SampleRate44100 SampleRate = 44100
	// SampleRate48000 represents professional audio at 48 kHz
	SampleRate48000 SampleRate = 48000
)

// ChannelCount represents number of audio channels
type ChannelCount int

// Channel configurations.
const (
	// Mono represents single-channel audio
	Mono ChannelCount = 1
	// Stereo represents dual-channel audio
	Stereo ChannelCount = 2
)

// Codec represents the audio encoding format.
type Codec string

// Audio codecs for encoding.
const (
	// CodecPCM16LE is 16-bit signed little-endian PCM
	CodecPCM16LE Codec = "pcm_s16le"
	// CodecPCM24LE is 24-bit signed little-endian PCM
	CodecPCM24LE Codec = "pcm_s24le"
	// CodecFLAC is Free Lossless Audio Codec
	CodecFLAC Codec = "flac"
)

// Format defines complete audio format specification.
type Format struct {
	SampleRate SampleRate
	Channels   ChannelCount
	Codec      Codec
}

// Standard formats
var (
	// FormatStoryWAV defines the standard audio format for mono news stories (48kHz, 16-bit PCM).
	FormatStoryWAV = Format{
		SampleRate: SampleRate48000,
		Channels:   Mono,
		Codec:      CodecPCM16LE,
	}

	// FormatJingleWAV defines the standard audio format for stereo jingles (48kHz, 16-bit PCM).
	FormatJingleWAV = Format{
		SampleRate: SampleRate48000,
		Channels:   Stereo,
		Codec:      CodecPCM16LE,
	}
)

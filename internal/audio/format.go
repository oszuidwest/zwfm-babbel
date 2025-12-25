package audio

import "fmt"

// SampleRate represents audio sample rate in Hz
type SampleRate int

const (
	SampleRate44100 SampleRate = 44100
	SampleRate48000 SampleRate = 48000
)

func (s SampleRate) String() string {
	return fmt.Sprintf("%d", s)
}

// ChannelCount represents number of audio channels
type ChannelCount int

const (
	Mono   ChannelCount = 1
	Stereo ChannelCount = 2
)

func (c ChannelCount) String() string {
	return fmt.Sprintf("%d", c)
}

// AudioCodec represents the audio encoding format
type AudioCodec string

const (
	CodecPCM16LE AudioCodec = "pcm_s16le"
	CodecPCM24LE AudioCodec = "pcm_s24le"
	CodecFLAC    AudioCodec = "flac"
)

// AudioFormat defines complete audio format specification
type AudioFormat struct {
	SampleRate SampleRate
	Channels   ChannelCount
	Codec      AudioCodec
}

// Standard formats
var (
	FormatStoryWAV = AudioFormat{
		SampleRate: SampleRate48000,
		Channels:   Mono,
		Codec:      CodecPCM16LE,
	}

	FormatJingleWAV = AudioFormat{
		SampleRate: SampleRate48000,
		Channels:   Stereo,
		Codec:      CodecPCM16LE,
	}
)

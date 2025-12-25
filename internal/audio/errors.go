package audio

import "fmt"

// Operation represents the type of audio operation
type Operation string

const (
	OpConvert        Operation = "convert"
	OpGetDuration    Operation = "get_duration"
	OpCreateBulletin Operation = "create_bulletin"
)

// AudioError represents a structured audio processing error
type AudioError struct {
	Op         Operation
	FilePath   string
	Command    string
	Stderr     string
	Underlying error
}

func (e *AudioError) Error() string {
	if e.Underlying != nil {
		return fmt.Sprintf("audio %s failed for %s: %v", e.Op, e.FilePath, e.Underlying)
	}
	return fmt.Sprintf("audio %s failed for %s", e.Op, e.FilePath)
}

func (e *AudioError) Unwrap() error {
	return e.Underlying
}

// NewConversionError creates an error for audio conversion failures
func NewConversionError(inputPath string, stderr string, err error) *AudioError {
	return &AudioError{
		Op:         OpConvert,
		FilePath:   inputPath,
		Stderr:     stderr,
		Underlying: err,
	}
}

// NewDurationError creates an error for duration extraction failures
func NewDurationError(filePath string, stderr string, err error) *AudioError {
	return &AudioError{
		Op:         OpGetDuration,
		FilePath:   filePath,
		Stderr:     stderr,
		Underlying: err,
	}
}

// NewBulletinError creates an error for bulletin generation failures
func NewBulletinError(outputPath string, stderr string, err error) *AudioError {
	return &AudioError{
		Op:         OpCreateBulletin,
		FilePath:   outputPath,
		Stderr:     stderr,
		Underlying: err,
	}
}

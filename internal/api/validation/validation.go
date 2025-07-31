// Package validation provides request validation utilities for the API.
package validation

import (
	"fmt"
	"mime/multipart"
	"path/filepath"
	"strings"
)

// AllowedAudioExtensions defines the allowed audio file extensions
var AllowedAudioExtensions = map[string]bool{
	".wav":  true,
	".mp3":  true,
	".m4a":  true,
	".aac":  true,
	".ogg":  true,
	".flac": true,
	".opus": true,
}

// AllowedAudioMimeTypes defines the allowed audio MIME types
var AllowedAudioMimeTypes = map[string]bool{
	"audio/wav":       true,
	"audio/wave":      true,
	"audio/x-wav":     true,
	"audio/mpeg":      true,
	"audio/mp3":       true,
	"audio/mp4":       true,
	"audio/aac":       true,
	"audio/ogg":       true,
	"audio/flac":      true,
	"audio/opus":      true,
	"application/ogg": true,
}

// MaxAudioFileSize defines the maximum allowed audio file size (100MB)
const MaxAudioFileSize = 100 * 1024 * 1024

// ValidateAudioFile validates an uploaded audio file
func ValidateAudioFile(fileHeader *multipart.FileHeader) error {
	if fileHeader == nil {
		return fmt.Errorf("no file provided")
	}

	// Check file size
	if fileHeader.Size > MaxAudioFileSize {
		return fmt.Errorf("file size exceeds maximum allowed size of %d MB", MaxAudioFileSize/(1024*1024))
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(fileHeader.Filename))
	if !AllowedAudioExtensions[ext] {
		return fmt.Errorf("invalid file extension: %s. Allowed extensions: wav, mp3, m4a, aac, ogg, flac, opus", ext)
	}

	// Open file to check content type
	file, err := fileHeader.Open()
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	// Read first 512 bytes to detect content type
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Detect content type from file content
	contentType := detectAudioContentType(buffer[:n])
	if contentType == "" || !AllowedAudioMimeTypes[contentType] {
		return fmt.Errorf("invalid audio file format. Please upload a valid audio file (wav, mp3, m4a, aac, ogg, flac, opus)")
	}

	return nil
}

// detectAudioContentType detects audio content type from file bytes
func detectAudioContentType(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	// WAV file signature
	if string(data[0:4]) == "RIFF" && len(data) > 8 && string(data[8:12]) == "WAVE" {
		return "audio/wav"
	}

	// MP3 file signatures
	if (data[0] == 0xFF && (data[1]&0xE0) == 0xE0) || // MPEG audio frame
		string(data[0:3]) == "ID3" { // ID3 tag
		return "audio/mpeg"
	}

	// OGG file signature
	if string(data[0:4]) == "OggS" {
		return "audio/ogg"
	}

	// FLAC file signature
	if string(data[0:4]) == "fLaC" {
		return "audio/flac"
	}

	// M4A/AAC (MP4 container)
	if len(data) > 11 {
		if string(data[4:8]) == "ftyp" {
			brand := string(data[8:12])
			if brand == "M4A " || brand == "mp42" || brand == "isom" {
				return "audio/mp4"
			}
		}
	}

	return ""
}

// SanitizeFilename removes potentially dangerous characters from filenames
func SanitizeFilename(filename string) string {
	// Get the base name without directory
	filename = filepath.Base(filename)

	// Remove any characters that could be used for directory traversal
	filename = strings.ReplaceAll(filename, "..", "")
	filename = strings.ReplaceAll(filename, "/", "")
	filename = strings.ReplaceAll(filename, "\\", "")

	// Replace spaces with underscores
	filename = strings.ReplaceAll(filename, " ", "_")

	// Remove any other potentially problematic characters
	filename = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, filename)

	return filename
}

package testutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// CorruptOpus creates an Ogg/Opus recording with a decodable first audio
// packet and invalid later packets. Recomputed page checksums keep the
// container valid, so a first-frame probe cannot detect the later corruption.
func CorruptOpus(t *testing.T, ffmpegPath string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "late-corruption.opus")
	// #nosec G204 -- trusted test binary and fixed fixture-generation arguments.
	cmd := exec.CommandContext(t.Context(), ffmpegPath, "-v", "error", "-f", "lavfi", "-i",
		"sine=frequency=440:duration=2", "-c:a", "libopus", "-y", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate Opus fixture: %v; %s", err, output)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed filename in t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	packets := 0
	for offset := 0; offset < len(data); {
		if offset+27 > len(data) || !bytes.Equal(data[offset:offset+4], []byte("OggS")) || data[offset+5]&1 != 0 {
			t.Fatal("unexpected Ogg page or continued packet in generated fixture")
		}
		segments := int(data[offset+26])
		body := offset + 27 + segments
		if body > len(data) {
			t.Fatal("truncated Ogg segment table")
		}
		packetStart := body
		for _, size := range data[offset+27 : body] {
			body += int(size)
			if body > len(data) {
				t.Fatal("truncated Ogg packet")
			}
			if size < 255 {
				packets++
				// Keep OpusHead, OpusTags and the first audio packet intact.
				if packets > 3 {
					for i := packetStart; i < body; i++ {
						data[i] = 0xff // Invalid Opus TOC/frame-count combination.
					}
				}
				packetStart = body
			}
		}
		clear(data[offset+22 : offset+26])
		binary.LittleEndian.PutUint32(data[offset+22:], oggCRC(data[offset:body]))
		offset = body
	}
	if packets < 10 {
		t.Fatalf("generated only %d packets", packets)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G703 -- fixed filename in t.TempDir, not an input path.
		t.Fatal(err)
	}
	return path
}

func oggCRC(data []byte) uint32 {
	var crc uint32
	for _, value := range data {
		crc ^= uint32(value) << 24
		for range 8 {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ 0x04c11db7 // Ogg's non-reflected CRC polynomial.
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// RequireDecoderError skips only the real-codec case when the installed FFmpeg
// tolerates the fixture. FFmpeg 6.1.1 divides integer counters when computing
// max_error_rate, rounding to zero if even one frame decoded successfully:
// https://github.com/FFmpeg/FFmpeg/blob/n6.1.1/fftools/ffmpeg.c#L1223-L1228
// Deterministic exit-status tests must still run on those versions.
func RequireDecoderError(t *testing.T, ffmpegPath, input string) {
	t.Helper()
	// #nosec G204 -- trusted test binary and test-owned fixture path.
	output, err := exec.CommandContext(t.Context(), ffmpegPath, "-v", "error", "-i", input, "-f", "null", "-").CombinedOutput()
	if err == nil {
		t.Skip("installed FFmpeg tolerates late corrupt packets instead of reporting decoder exit 69")
	}
	if exit, ok := errors.AsType[*exec.ExitError](err); !ok || exit.ExitCode() != 69 {
		t.Fatalf("fixture decode = %v, want exit 69; %s", err, output)
	}
}

// DecoderErrorTools simulates successful first-frame probing followed by a
// decoder failure, independent of the host FFmpeg version or codec support.
func DecoderErrorTools(t *testing.T) (ffmpeg, ffprobe string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("requires shell executables")
	}
	dir := t.TempDir()
	for name, script := range map[string]string{
		"ffmpeg":  "#!/bin/sh\nexit 69\n",
		"ffprobe": "#!/bin/sh\nprintf '960,1\\n'\n",
	} {
		// #nosec G306 -- executable test scripts in a private t.TempDir.
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "ffmpeg"), filepath.Join(dir, "ffprobe")
}

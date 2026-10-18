package testutil

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// CorruptOpus creates an Ogg/Opus recording with a decodable first audio
// packet and invalid later packets. Recomputed page checksums keep the
// container valid, so a first-frame probe cannot detect the later corruption.
func CorruptOpus(t *testing.T, ffmpegPath string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "late-corruption.opus")
	cmd := exec.CommandContext(t.Context(), ffmpegPath, "-v", "error", "-f", "lavfi", "-i",
		"sine=frequency=440:duration=2", "-c:a", "libopus", "-y", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate Opus fixture: %v; %s", err, output)
	}
	data, err := os.ReadFile(path)
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
		var crc uint32
		for _, value := range data[offset:body] {
			crc ^= uint32(value) << 24
			for range 8 {
				if crc&0x80000000 != 0 {
					crc = crc<<1 ^ 0x04c11db7 // Ogg's non-reflected CRC polynomial.
				} else {
					crc <<= 1
				}
			}
		}
		binary.LittleEndian.PutUint32(data[offset+22:], crc)
		offset = body
	}
	if packets < 10 {
		t.Fatalf("generated only %d packets", packets)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

package models

import "testing"

func TestStoryAfterFind(t *testing.T) {
	tests := []struct {
		name          string
		story         Story
		wantTitle     string
		wantText      string
		wantVoiceName string
		wantAudioURL  string
	}{
		{
			name:         "decodes named HTML entities",
			story:        Story{ID: 1, Title: "Tom &amp; Jerry", Text: "Use &lt;b&gt; tags"},
			wantTitle:    "Tom & Jerry",
			wantText:     "Use <b> tags",
			wantAudioURL: "/stories/1/audio",
		},
		{
			name:         "decodes numeric HTML entities",
			story:        Story{ID: 1, Title: "caf&#233;", Text: "&#169; 2024"},
			wantTitle:    "café",
			wantText:     "© 2024",
			wantAudioURL: "/stories/1/audio",
		},
		{
			name:         "leaves plain text unchanged",
			story:        Story{ID: 1, Title: "Plain title", Text: "Plain text content"},
			wantTitle:    "Plain title",
			wantText:     "Plain text content",
			wantAudioURL: "/stories/1/audio",
		},
		{
			name:         "is idempotent on already-decoded text",
			story:        Story{ID: 1, Title: "Tom & Jerry", Text: "Text with < and > symbols"},
			wantTitle:    "Tom & Jerry",
			wantText:     "Text with < and > symbols",
			wantAudioURL: "/stories/1/audio",
		},
		{
			name:          "populates VoiceName from Voice relation",
			story:         Story{ID: 1, Voice: &Voice{Name: "Test Voice"}},
			wantVoiceName: "Test Voice",
			wantAudioURL:  "/stories/1/audio",
		},
		{
			name:         "leaves VoiceName empty when Voice is nil",
			story:        Story{ID: 1, Voice: nil},
			wantAudioURL: "/stories/1/audio",
		},
		{
			name:         "generates audio URL from ID",
			story:        Story{ID: 42},
			wantAudioURL: "/stories/42/audio",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.story
			if err := s.AfterFind(nil); err != nil {
				t.Fatalf("AfterFind error: %v", err)
			}
			if s.Title != tt.wantTitle {
				t.Errorf("Title = %q, want %q", s.Title, tt.wantTitle)
			}
			if s.Text != tt.wantText {
				t.Errorf("Text = %q, want %q", s.Text, tt.wantText)
			}
			if s.VoiceName != tt.wantVoiceName {
				t.Errorf("VoiceName = %q, want %q", s.VoiceName, tt.wantVoiceName)
			}
			if s.AudioURL != tt.wantAudioURL {
				t.Errorf("AudioURL = %q, want %q", s.AudioURL, tt.wantAudioURL)
			}
		})
	}
}

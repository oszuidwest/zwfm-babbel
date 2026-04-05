package models

import (
	"testing"
)

func TestStoryAfterFind_DecodesHTMLEntities(t *testing.T) {
	s := &Story{
		ID:    1,
		Title: "Tom &amp; Jerry",
		Text:  "Use &lt;b&gt; tags",
	}
	if err := s.AfterFind(nil); err != nil {
		t.Fatalf("AfterFind error: %v", err)
	}
	if s.Title != "Tom & Jerry" {
		t.Errorf("Title = %q, want %q", s.Title, "Tom & Jerry")
	}
	if s.Text != "Use <b> tags" {
		t.Errorf("Text = %q, want %q", s.Text, "Use <b> tags")
	}
}

func TestStoryAfterFind_NumericEntities(t *testing.T) {
	s := &Story{
		ID:    1,
		Title: "caf&#233;",
		Text:  "&#169; 2024",
	}
	if err := s.AfterFind(nil); err != nil {
		t.Fatalf("AfterFind error: %v", err)
	}
	if s.Title != "café" {
		t.Errorf("Title = %q, want %q", s.Title, "café")
	}
	if s.Text != "© 2024" {
		t.Errorf("Text = %q, want %q", s.Text, "© 2024")
	}
}

func TestStoryAfterFind_PlainTextUnchanged(t *testing.T) {
	s := &Story{
		ID:    1,
		Title: "Plain title",
		Text:  "Plain text content",
	}
	if err := s.AfterFind(nil); err != nil {
		t.Fatalf("AfterFind error: %v", err)
	}
	if s.Title != "Plain title" {
		t.Errorf("Title changed unexpectedly to %q", s.Title)
	}
	if s.Text != "Plain text content" {
		t.Errorf("Text changed unexpectedly to %q", s.Text)
	}
}

func TestStoryAfterFind_IdempotentOnDecodedText(t *testing.T) {
	s := &Story{
		ID:    1,
		Title: "Tom & Jerry",
		Text:  "Text with < and > symbols",
	}
	if err := s.AfterFind(nil); err != nil {
		t.Fatalf("AfterFind error: %v", err)
	}
	if s.Title != "Tom & Jerry" {
		t.Errorf("Title = %q, want unchanged %q", s.Title, "Tom & Jerry")
	}
	if s.Text != "Text with < and > symbols" {
		t.Errorf("Text = %q, want unchanged", s.Text)
	}
}

func TestStoryAfterFind_PopulatesVoiceName(t *testing.T) {
	voice := &Voice{Name: "Test Voice"}
	s := &Story{ID: 1, Voice: voice}
	if err := s.AfterFind(nil); err != nil {
		t.Fatalf("AfterFind error: %v", err)
	}
	if s.VoiceName != "Test Voice" {
		t.Errorf("VoiceName = %q, want %q", s.VoiceName, "Test Voice")
	}
}

func TestStoryAfterFind_NilVoiceLeavesVoiceNameEmpty(t *testing.T) {
	s := &Story{ID: 1, Voice: nil}
	if err := s.AfterFind(nil); err != nil {
		t.Fatalf("AfterFind error: %v", err)
	}
	if s.VoiceName != "" {
		t.Errorf("VoiceName = %q, want empty", s.VoiceName)
	}
}

func TestStoryAfterFind_GeneratesAudioURL(t *testing.T) {
	s := &Story{ID: 42}
	if err := s.AfterFind(nil); err != nil {
		t.Fatalf("AfterFind error: %v", err)
	}
	if s.AudioURL != "/stories/42/audio" {
		t.Errorf("AudioURL = %q, want %q", s.AudioURL, "/stories/42/audio")
	}
}

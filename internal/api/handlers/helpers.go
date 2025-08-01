package handlers

import (
	"io"
	"mime/multipart"
	"os"
	"strings"
)

// saveFile saves a file to the specified path
// The dst path must be sanitized before calling this function
func saveFile(file multipart.File, dst string) error {
	// #nosec G304 - dst is sanitized by caller using validation.SanitizeFilename
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	_, err = io.Copy(out, file)
	return err
}

// joinStrings joins strings with a separator
func joinStrings(strs []string, sep string) string {
	return strings.Join(strs, sep)
}

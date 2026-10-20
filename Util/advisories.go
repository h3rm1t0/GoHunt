package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func ReadBoundedJSON(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if err != nil {
		return err
	}
	if len(b) > 8<<20 {
		return fmt.Errorf("JSON excede 8MiB: %s", path)
	}
	return StrictJSON(b, target)
}

func StrictJSON(b []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("JSON contém dados adicionais")
	}
	return nil
}

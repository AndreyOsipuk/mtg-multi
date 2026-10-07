package config

import (
	"fmt"
	"strconv"
)

// TypeTCPMSS - значение TCP MSS в байтах. 0 означает «не задано/выключено»;
// допустимые диапазоны для client-mss и client-mss-bulk разные, их
// проверяет Config.Validate.
type TypeTCPMSS struct {
	Value uint
}

func (t *TypeTCPMSS) Set(value string) error {
	mss, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return fmt.Errorf("value is not uint16 (%s): %w", value, err)
	}

	t.Value = uint(mss)

	return nil
}

func (t TypeTCPMSS) Get(defaultValue uint) uint {
	if t.Value == 0 {
		return defaultValue
	}

	return t.Value
}

func (t *TypeTCPMSS) UnmarshalJSON(data []byte) error {
	return t.Set(string(data))
}

func (t TypeTCPMSS) MarshalJSON() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeTCPMSS) String() string {
	return strconv.FormatUint(uint64(t.Value), 10)
}

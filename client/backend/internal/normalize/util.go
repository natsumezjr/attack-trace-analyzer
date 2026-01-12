package normalize

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"
)

const ECSVersion = "9.2.0"

func SHA1Hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func ParseTimeFlexible(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("empty time string")
	}

	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999-0700",
		"2006-01-02T15:04:05.999999999-0700",
		"2006-01-02T15:04:05.999999Z0700",
		"2006-01-02T15:04:05.999999999Z0700",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("unsupported time format")
}

func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]float64
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var ent float64
	length := float64(len(s))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := c / length
		ent -= p * math.Log2(p)
	}
	return ent
}

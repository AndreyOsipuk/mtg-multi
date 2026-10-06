package cli

import (
	"reflect"
	"testing"
)

func TestEnvInts(t *testing.T) {
	cases := map[string][]int{
		"":                 nil,
		"2,-2,203":         {2, -2, 203},
		" 4 , -4 ,x,0,, 5": {4, -4, 5},
	}

	for value, want := range cases {
		t.Setenv("MTG_TEST_INTS", value)

		if got := envInts("MTG_TEST_INTS"); !reflect.DeepEqual(got, want) {
			t.Errorf("envInts(%q) = %v, want %v", value, got, want)
		}
	}
}

package main

import "testing"

func TestParseSelection(t *testing.T) {
	cases := []struct {
		input string
		count int
		want  []int
		ok    bool
	}{
		{"", 3, []int{0, 1, 2}, true},
		{"all", 2, []int{0, 1}, true},
		{"1,3", 3, []int{0, 2}, true},
		{"2,2", 3, []int{1}, true},
		{"0", 3, nil, false},
		{"4", 3, nil, false},
		{"x", 3, nil, false},
		{",", 3, nil, false},
	}
	for _, tc := range cases {
		got, err := parseSelection(tc.input, tc.count)
		if (err == nil) != tc.ok {
			t.Fatalf("parseSelection(%q, %d) error = %v, want ok=%v", tc.input, tc.count, err, tc.ok)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("parseSelection(%q, %d) = %v, want %v", tc.input, tc.count, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("parseSelection(%q, %d) = %v, want %v", tc.input, tc.count, got, tc.want)
			}
		}
	}
}

package main

import "testing"

func TestCSVSafeCell(t *testing.T) {
	cases := map[string]string{
		"=cmd|' /C calc'!A0": "'=cmd|' /C calc'!A0",
		"+1+1":               "'+1+1",
		"-2+3":               "'-2+3",
		"@SUM(A1)":           "'@SUM(A1)",
		"  =1+1":             "'  =1+1",
		"web-01":             "web-01",
		"9.8":                "9.8",
		"":                   "",
	}
	for input, want := range cases {
		if got := csvSafeCell(input); got != want {
			t.Fatalf("csvSafeCell(%q) = %q，期望 %q", input, got, want)
		}
	}
}

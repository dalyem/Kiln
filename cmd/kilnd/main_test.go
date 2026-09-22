package main

import "testing"

func TestIsLoopback(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if !isLoopback(host) {
			t.Fatalf("expected %q to be loopback", host)
		}
	}
	for _, host := range []string{"0.0.0.0", "192.0.2.10", "example.test"} {
		if isLoopback(host) {
			t.Fatalf("expected %q not to be loopback", host)
		}
	}
}

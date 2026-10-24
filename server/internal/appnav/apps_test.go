package appnav

import (
	"strings"
	"testing"
)

func TestGrantedLinksAreSafeAndBounded(t *testing.T) {
	good := App{ID: "granted", Name: "Notes <safe>", LaunchURL: "https://notes.example/"}
	in := []App{good, {ID: "own", Name: "Own", LaunchURL: "https://own.example/"}, {ID: "bad", Name: "Unsafe", LaunchURL: "javascript:alert(1)"}, {ID: "creds", Name: "Unsafe", LaunchURL: "https://user:pass@example.com/"}, {ID: "missing", Name: "No launch"}, {ID: "slash", Name: "Bad", LaunchURL: "https://example.com/\\evil"}, {ID: "control", Name: "Bad", LaunchURL: "https://example.com/\n"}, {ID: "long", Name: strings.Repeat("x", 201), LaunchURL: "https://example.com/"}, good}
	got := Clean(in, "own")
	if len(got) != 1 || got[0] != good {
		t.Fatalf("unexpected safe grant list: %#v", got)
	}
	if len(Decode("invalid")) != 0 || len(Decode(Encode(got))) != 1 {
		t.Fatal("stored grant decoding must fail closed")
	}
	if len(Clean(nil, "own")) != 0 {
		t.Fatal("missing claims must not grant links")
	}
}

package keys

import "testing"

func TestPepper(t *testing.T) {
	dir := t.TempDir()
	p, err := LoadPepper(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := p.Hash("proof")
	if h == "proof" || len(h) != 64 || !p.Equal(h, "proof") || p.Equal(h, "other") {
		t.Fatal("pepper hash")
	}
	p2, _ := LoadPepper(dir) // persisted: the same key is loaded again
	if p2.Hash("proof") != h {
		t.Fatal("pepper must persist")
	}
	other, _ := LoadPepper(t.TempDir())
	if other.Hash("proof") == h {
		t.Fatal("different data dirs must have different peppers")
	}
}

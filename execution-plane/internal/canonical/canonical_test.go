package canonical

import "testing"

// Vectors generated with the Python control plane (asvas.canonical); see control-plane/tests/test_canonical.py.
func TestMatchesPythonVectors(t *testing.T) {
	v, _ := Normalize(map[string]any{
		"b": []any{1, true, nil, "x\"y\\z"}, "a": map[string]any{"z": "é☃", "y": "\n\t<&>"}, "emoji": "😀",
	})
	got, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"y":"\n\t<&>","z":"\u00e9\u2603"},"b":[1,true,null,"x\"y\\z"],"emoji":"\ud83d\ude00"}`
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	v2, _ := Normalize(map[string]any{"assessment_id": "a1", "job_id": "j1", "tool_id": "http.allowed_methods",
		"target": map[string]any{"scheme": "http", "host": "127.0.0.1", "port": 18080}, "params": map[string]any{"path": "/"}})
	s2, _ := Marshal(v2)
	if got := SHA256Hex(s2); got != "397fc8010c1a9f6de954f551b4511a73c7eb997c55c4a8e2b224006fe297cee9" {
		t.Fatalf("binding hash differs from Python: %s", got)
	}
}

func TestRejectsFloats(t *testing.T) {
	v, _ := Normalize(map[string]any{"x": 1.5})
	if _, err := Marshal(v); err == nil {
		t.Fatal("float accepted")
	}
}

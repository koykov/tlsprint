package tlsvector

import (
	"testing"
)

func TestVector(t *testing.T) {
	for i := 0; i < len(stages); i++ {
		st := &stages[i]
		t.Run(st.key, func(t *testing.T) {
			t.Run("client hello/ja3", func(t *testing.T) {
				vec := New()
				err := vec.Parse(st.flows[0])
				if err != nil {
					t.Fatal(err)
				}
				h := vec.JA3()
				t.Log(h)
			})
		})
	}
}

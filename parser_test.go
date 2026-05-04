package tlsvector

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type stage struct {
	key string

	origin []byte
	flows  [][]byte
	chfmt  []byte
	shfmt  []byte
}

var (
	stages    []stage
	stagesReg = map[string]int{}
)

func init() {
	var (
		reFlow    = regexp.MustCompile(`>>> Flow (\d+).*`)
		rePayload = regexp.MustCompile(`^\S+\s+((?:[0-9a-fA-F]{2}\s+)*[0-9a-fA-F]{2})`)
	)

	_ = filepath.Walk("testdata", func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(path) == ".raw" {
			st := stage{flows: make([][]byte, 15)}
			st.key = strings.Replace(filepath.Base(path), ".raw", "", 1)
			st.origin, _ = os.ReadFile(path)

			buf := make([]byte, 0, 1024)
			rdr := bytes.NewReader(st.origin)
			scr := bufio.NewScanner(rdr)
			var flowID int64 = -1
			for scr.Scan() {
				line := scr.Bytes()
				if m := reFlow.FindSubmatch(line); len(m) > 0 {
					if flowID >= 0 {
						st.flows[flowID] = append(st.flows[flowID], buf...)
						buf = buf[:0]
					}
					if flowID, err = strconv.ParseInt(string(m[1]), 10, 64); err != nil {
						panic(err)
					}
					flowID--
					continue
				}
				if m := rePayload.FindSubmatch(line); len(m) > 0 {
					pl := m[1]
					for len(pl) > 0 {
						p2 := pl[:2]
						pl = pl[2:]
						b2, err := strconv.ParseInt(string(p2), 16, 64)
						if err != nil {
							panic(err)
						}
						buf = append(buf, byte(b2))
						pl = bytes.TrimLeft(pl, " ")
					}
					continue
				}
				panic(fmt.Sprintf("wring line format: %s", string(line)))
			}

			if len(buf) > 0 {
				st.flows[flowID] = append(st.flows[flowID], buf...)
			}

			st.chfmt, _ = os.ReadFile(strings.Replace(path, ".raw", ".chfmt.txt", 1))
			st.shfmt, _ = os.ReadFile(strings.Replace(path, ".raw", ".shfmt.txt", 1))
			stages = append(stages, st)
			stagesReg[st.key] = len(stages) - 1
			return nil
		}
		return nil
	})
}

func getStage(key string) *stage {
	i, ok := stagesReg[key]
	if !ok {
		return nil
	}
	return &stages[i]
}

func getTBName(tb testing.TB) string {
	key := tb.Name()
	return key[strings.Index(key, "/")+1:]
}

func TestParser(t *testing.T) {
	for i := 0; i < len(stages); i++ {
		st := &stages[i]
		t.Run(st.key, func(t *testing.T) {
			t.Run("client hello", func(t *testing.T) {
				vec := New()
				err := vec.Parse(st.flows[0])
				if err != nil {
					t.Fatal(err)
				}
				s := vec.String()
				if !bytes.Equal([]byte(s), st.chfmt) {
					t.Errorf("mismatch result and expectation")
				}
			})
			t.Run("server hello", func(t *testing.T) {
				if len(st.shfmt) == 0 {
					t.Skip()
				}
				vec := New()
				err := vec.Parse(st.flows[1])
				if err != nil {
					t.Fatal(err)
				}
				s := vec.String()
				if !bytes.Equal([]byte(s), st.shfmt) {
					t.Errorf("mismatch result and expectation")
				}
			})
		})
	}
}

func BenchmarkParser(b *testing.B) {
	benchfn := func(b *testing.B, st *stage, flowID int) {
		vec := New()
		b.SetBytes(int64(len(st.flows[flowID])))
		b.ReportAllocs()
		b.ResetTimer()
		for j := 0; j < b.N; j++ {
			vec.Reset()
			_ = vec.Parse(st.flows[flowID])
		}
	}
	for i := 0; i < len(stages); i++ {
		st := &stages[i]
		b.Run(st.key, func(b *testing.B) {
			b.Run("client hello", func(b *testing.B) { benchfn(b, st, 0) })
			b.Run("server hello", func(b *testing.B) { benchfn(b, st, 1) })
		})
	}
}

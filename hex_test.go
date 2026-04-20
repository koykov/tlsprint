package tlsvector

import "testing"

func TestHex(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		expect uint64
		err    error
	}{
		{
			name: "single digit 0",
			data: []byte("0"),
		},
		{
			name:   "single digit 9",
			data:   []byte("9"),
			expect: 9,
		},
		{
			name:   "single digit A",
			data:   []byte("A"),
			expect: 10,
		},
		{
			name:   "single digit F",
			data:   []byte("F"),
			expect: 15,
		},
		{
			name:   "two digits FF",
			data:   []byte("FF"),
			expect: 255,
		},
		{
			name:   "two digits 10",
			data:   []byte("10"),
			expect: 16,
		},
		{
			name:   "lowercase letters",
			data:   []byte("1a2b"),
			expect: 0x1A2B,
		},
		{
			name:   "mixed case DEADBEEF",
			data:   []byte("DeadBeef"),
			expect: 0xDEADBEEF,
		},
		{
			name:   "maximum 16 digits",
			data:   []byte("FFFFFFFFFFFFFFFF"),
			expect: 0xFFFFFFFFFFFFFFFF,
		},
		{
			name:   "16 digits with leading zeros",
			data:   []byte("0000000000000001"),
			expect: 1,
		},
		{
			name:   "15 digits max value",
			data:   []byte("7FFFFFFFFFFFFFFF"),
			expect: 0x7FFFFFFFFFFFFFFF,
		},
		{
			name:   "typical 32-bit value",
			data:   []byte("DEADBEEF"),
			expect: 0xDEADBEEF,
		},
		{
			name: "all zeros",
			data: []byte("0000000000000000"),
		},

		{
			name: "empty data",
			data: []byte(""),
			err:  ErrNoData,
		},
		{
			name: "17 digits (too long)",
			data: []byte("FFFFFFFFFFFFFFFFF"),
			err:  ErrHexTooLong,
		},
		{
			name: "20 digits",
			data: []byte("1234567890ABCDEF1234"),
			err:  ErrHexTooLong,
		},
		{
			name:   "edge case",
			data:   []byte("1"),
			expect: 1,
		},
		{
			name:   "edge case",
			data:   []byte("10"),
			expect: 16,
		},
		{
			name:   "edge case",
			data:   []byte("100"),
			expect: 256,
		},
		{
			name:   "edge case",
			data:   []byte("1000"),
			expect: 4096,
		},
		{
			name:   "edge case",
			data:   []byte("7FFFFFFFFFFFFFFF"),
			expect: 0x7FFFFFFFFFFFFFFF,
		},
		{
			name:   "edge case",
			data:   []byte("8000000000000000"),
			expect: 0x8000000000000000,
		},
		{
			name:   "edge case",
			data:   []byte("FFFFFFFFFFFFFFFF"),
			expect: 0xFFFFFFFFFFFFFFFF,
		},
		{
			name:   "edge case",
			data:   []byte("0000000000000001"),
			expect: 1,
		},
		{
			name:   "edge case",
			data:   []byte("0000000000000010"),
			expect: 16,
		},
		{
			name:   "edge case",
			data:   []byte("FFFFFFFFFFFFFFFE"),
			expect: 0xFFFFFFFFFFFFFFFE,
		},

		{
			name: "invalid character G",
			data: []byte("G"),
			err:  ErrHexBadByte,
		},
		{
			name: "invalid character Z",
			data: []byte("1Z3"),
			err:  ErrHexBadByte,
		},
		{
			name: "invalid character lowercase g",
			data: []byte("aBg"),
			err:  ErrHexBadByte,
		},
		{
			name: "invalid character symbol",
			data: []byte("12@4"),
			err:  ErrHexBadByte,
		},
		{
			name: "invalid character space",
			data: []byte("AB C"),
			err:  ErrHexBadByte,
		},
		{
			name: "invalid character newline",
			data: []byte("AB\nC"),
			err:  ErrHexBadByte,
		},
		{
			name: "mixed valid and invalid",
			data: []byte("DEADBEEFZ"),
			err:  ErrHexBadByte,
		},
		{
			name: "invalid at beginning",
			data: []byte("X123"),
			err:  ErrHexBadByte,
		},
		{
			name: "invalid at end",
			data: []byte("123X"),
			err:  ErrHexBadByte,
		},

		{
			name: "digit 0 after invalid check",
			data: []byte("0\x00"),
			err:  ErrHexBadByte,
		},
		{
			name: "very long invalid",
			data: []byte("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"),
			err:  ErrHexTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := x2u(tt.data)

			if err != tt.err {
				t.Errorf("x2u() error = %v, err %v", err, tt.err)
				return
			}

			if tt.err != nil && got != 0 {
				t.Errorf("x2u() got = %v, expect 0 when error occurs", got)
				return
			}

			if got != tt.expect {
				t.Errorf("x2u() = %v, expect %v", got, tt.expect)
			}
		})
	}
}

func BenchmarkHex(b *testing.B) {
	testCases := []struct {
		name  string
		input []byte
	}{
		{"4 digits", []byte("DEAD")},
		{"8 digits", []byte("DEADBEEF")},
		{"16 digits", []byte("DEADBEEFDEADBEEF")},
		{"16 digits max", []byte("FFFFFFFFFFFFFFFF")},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = x2u(tc.input)
			}
		})
	}
}

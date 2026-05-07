package tlsvector

// Check value is a GREASE (Generate Random Extensions And Sustain Extensibility) value.
func isGREASE(value uint16) bool {
	return (value&0x0F0F) == 0x0A0A && (value>>8) == (value&0x00FF)
}

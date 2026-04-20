package tlsvector

import "sync"

var p = sync.Pool{New: func() any { return &vector{} }}

func Acquire() Interface {
	return p.Get().(*vector)
}

func Release(ctx Interface) {
	ctx.Reset()
	p.Put(ctx)
}

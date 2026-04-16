package tlsprint

import "sync"

var p = sync.Pool{New: func() any { return &Ctx{} }}

func AcquireCtx() *Ctx {
	return p.Get().(*Ctx)
}

func ReleaseCtx(ctx *Ctx) {
	ctx.Reset()
	p.Put(ctx)
}

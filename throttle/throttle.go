// Package throttle 模拟弱网：限制带宽并增加延迟。
//
// 慢网络下才会暴露的问题——加载顺序、超时处理、进度反馈——
// 在本机千兆环境里基本看不出来，因此需要主动把链路压慢。
//
// 限速通过包装 Body 实现：读取时按令牌桶等待，
// 阻塞的正是负责把数据搬给客户端的那个 goroutine，
// 因此不需要额外的调度，效果与真实窄带链路一致。
package throttle

import (
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/dreamsxin/go-netsniffer/models"
)

// 单次读取的字节上限。一次读太多会把等待时间攒成一次长卡顿，
// 也会让客户端断开后迟迟无法收尾，因此按速率算出约 100ms 的分片。
const (
	chunkTarget = 100 * time.Millisecond
	minChunk    = 512
	maxChunk    = 32 << 10
)

// Limiter 施加限速与延迟，并发安全，支持热更新。
type Limiter struct {
	mu    sync.RWMutex
	cfg   models.ThrottleConfig
	urlRe *regexp.Regexp
	// down 与 up 是全局共享的令牌桶：真实链路的带宽是所有连接共用的，
	// 每条连接独立限速会让并发下载总量远超设定值
	down *bucket
	up   *bucket
}

func New(cfg models.ThrottleConfig) *Limiter {
	l := &Limiter{}
	l.Load(cfg)
	return l
}

// Load 替换配置。返回错误时旧配置继续生效。
func (l *Limiter) Load(cfg models.ThrottleConfig) error {
	cfg.Normalize()

	var re *regexp.Regexp
	if cfg.URLRegex != "" {
		compiled, err := regexp.Compile(cfg.URLRegex)
		if err != nil {
			return err
		}
		re = compiled
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.cfg, l.urlRe = cfg, re
	l.down = newBucket(kbpsToBytes(cfg.DownKbps))
	l.up = newBucket(kbpsToBytes(cfg.UpKbps))
	return nil
}

// Config 返回当前生效的配置（已归一化）
func (l *Limiter) Config() models.ThrottleConfig {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cfg
}

// Effective 表示当前配置是否真的会产生限制
func (l *Limiter) Effective() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cfg.Effective()
}

// kbpsToBytes 把 kbit/s 换成 byte/s。0 或负数表示不限。
func kbpsToBytes(kbps int) float64 {
	if kbps <= 0 {
		return 0
	}
	return float64(kbps) * 1000 / 8
}

// ApplyRequest 施加延迟与上行限速。
//
// 延迟直接在这里 sleep：阻塞的是处理该连接的 goroutine，
// 客户端观察到的就是一次变慢的往返，与真实高 RTT 链路一致。
func (l *Limiter) ApplyRequest(req *http.Request) {
	if req == nil {
		return
	}
	cfg, up, ok := l.pick(req.URL.String())
	if !ok {
		return
	}

	if cfg.LatencyMs > 0 {
		sleepCtx(req, time.Duration(cfg.LatencyMs)*time.Millisecond)
	}
	if up != nil && req.Body != nil {
		req.Body = wrap(req.Body, up)
	}
}

// ApplyResponse 对响应体施加下行限速。
func (l *Limiter) ApplyResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	// 101 之后 Body 是双向帧流，goproxy 会把它断言成 io.ReadWriter 直接对拷。
	// 包一层只读的限速器会让断言失败，WebSocket 直接不可用。
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return
	}

	url := ""
	if resp.Request != nil && resp.Request.URL != nil {
		url = resp.Request.URL.String()
	}
	cfg, _, ok := l.pick(url)
	if !ok || cfg.DownKbps <= 0 {
		return
	}

	l.mu.RLock()
	down := l.down
	l.mu.RUnlock()
	if down != nil {
		resp.Body = wrap(resp.Body, down)
	}
}

// pick 判断该 URL 是否在生效范围内，并取回上行桶。
func (l *Limiter) pick(url string) (models.ThrottleConfig, *bucket, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if !l.cfg.Effective() {
		return l.cfg, nil, false
	}
	if l.urlRe != nil && !l.urlRe.MatchString(url) {
		return l.cfg, nil, false
	}
	return l.cfg, l.up, true
}

// sleepCtx 在等待期间尊重请求的取消信号，
// 否则客户端断开后仍要干等满整个延迟才收尾。
func sleepCtx(req *http.Request, d time.Duration) {
	ctx := req.Context()
	if ctx == nil {
		time.Sleep(d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// bucket 是按字节计的令牌桶。
type bucket struct {
	mu sync.Mutex
	// rate 是每秒补充的字节数
	rate float64
	// capacity 允许一秒的突发，避免小请求被无谓拖慢
	capacity float64
	tokens   float64
	last     time.Time
	// chunk 是单次读取上限，按速率算出使每次等待约 chunkTarget
	chunk int
}

func newBucket(bytesPerSec float64) *bucket {
	if bytesPerSec <= 0 {
		return nil
	}
	chunk := int(bytesPerSec * chunkTarget.Seconds())
	if chunk < minChunk {
		chunk = minChunk
	}
	if chunk > maxChunk {
		chunk = maxChunk
	}
	return &bucket{
		rate:     bytesPerSec,
		capacity: bytesPerSec,
		tokens:   bytesPerSec,
		last:     time.Now(),
		chunk:    chunk,
	}
}

// reserve 扣除 n 个字节，返回为此需要等待的时长。
func (b *bucket) reserve(n int) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	b.last = now
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}

	b.tokens -= float64(n)
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

type limitedReader struct {
	inner io.ReadCloser
	b     *bucket
}

func wrap(body io.ReadCloser, b *bucket) io.ReadCloser {
	return &limitedReader{inner: body, b: b}
}

func (r *limitedReader) Read(p []byte) (int, error) {
	if len(p) > r.b.chunk {
		p = p[:r.b.chunk]
	}
	n, err := r.inner.Read(p)
	if n > 0 {
		// 先读后等：等待的是"这批字节占用链路的时间"，
		// 与真实链路上数据慢慢到达的效果一致
		if d := r.b.reserve(n); d > 0 {
			time.Sleep(d)
		}
	}
	return n, err
}

func (r *limitedReader) Close() error { return r.inner.Close() }

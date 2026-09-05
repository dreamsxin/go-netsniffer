// Package tcpstream 把 IP 侧抓到的 TCP 报文重组成双向字节流。
//
// 单个报文只能看到片段，遇到乱序、重传、跨包切分就无法读出应用层内容。
// 重组按序列号把两个方向各自拼成连续字节流，界面即可"跟随流"查看。
//
// 重组需要为每条连接维护缓冲，属于调试用途，默认关闭。
package tcpstream

import (
	"fmt"
	"sync"
	"time"

	"github.com/dreamsxin/go-netsniffer/models"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

// entry 是单条流的完整状态。
type entry struct {
	summary models.TCPStreamSummary
	// client 与 server 各留存前 maxBytes 字节
	client, server          []byte
	clientTrunc, serverTrunc bool
	// lastSeen 用于按空闲时间回收
	lastSeen time.Time
}

// Tracker 是对外的唯一入口。
//
// Assemble 只在抓包协程里调用（reassembly.Assembler 本身不支持并发），
// 而 Summaries / Detail 来自界面协程，因此流存储单独用互斥锁保护。
type Tracker struct {
	maxBytes   int
	maxStreams int
	idle       time.Duration

	assembler *reassembly.Assembler

	mu      sync.Mutex
	streams map[string]*entry
	// order 记录插入顺序，用于展示与超额判断
	order []string
	// dirty 表示自上次 TakeDirty 之后有过变化
	dirty bool
}

// New 创建跟踪器。cfg 必须已 Normalize。
func New(cfg models.TCPStreamConfig) *Tracker {
	t := &Tracker{
		maxBytes:   cfg.MaxStreamBytes,
		maxStreams: cfg.MaxStreams,
		idle:       time.Duration(cfg.IdleSeconds) * time.Second,
		streams:    make(map[string]*entry),
	}
	pool := reassembly.NewStreamPool(factory{t: t})
	t.assembler = reassembly.NewAssembler(pool)
	// 限制乱序缓冲页数：不设上限时对端持续发乱序包会让内存无界增长
	t.assembler.MaxBufferedPagesTotal = 4096
	t.assembler.MaxBufferedPagesPerConnection = 256
	return t
}

// Assemble 喂入一个报文。非 TCP 报文直接忽略。
func (t *Tracker) Assemble(packet gopacket.Packet) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}
	t.assembler.AssembleWithContext(netLayer.NetworkFlow(), tcp, context{ci: packet.Metadata().CaptureInfo})
}

// FlushIdle 关闭空闲超时的流，触发它们的 ReassemblyComplete。
// 不做这一步的话半开连接会一直占着内存。
func (t *Tracker) FlushIdle(now time.Time) {
	t.assembler.FlushCloseOlderThan(now.Add(-t.idle))
}

// FlushAll 冲刷全部流，停止抓包时调用
func (t *Tracker) FlushAll() {
	t.assembler.FlushAll()
}

// Summaries 返回流列表，按首次出现顺序。
func (t *Tracker) Summaries() []models.TCPStreamSummary {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]models.TCPStreamSummary, 0, len(t.order))
	for _, id := range t.order {
		if e := t.streams[id]; e != nil {
			out = append(out, e.summary)
		}
	}
	return out
}

// Detail 返回单条流的完整内容，供"跟随流"视图按需拉取。
func (t *Tracker) Detail(id string) (models.TCPStreamDetail, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e := t.streams[id]
	if e == nil {
		return models.TCPStreamDetail{}, false
	}
	// 载荷切片会被继续追加，必须复制后再交给调用方
	return models.TCPStreamDetail{
		TCPStreamSummary: e.summary,
		ClientPayload:    append([]byte(nil), e.client...),
		ServerPayload:    append([]byte(nil), e.server...),
		ClientTruncated:  e.clientTrunc,
		ServerTruncated:  e.serverTrunc,
	}, true
}

// TakeDirty 返回自上次调用以来是否有变化，并清除标记。
// 界面据此决定要不要重新拉取列表，避免无变化时的空推送。
func (t *Tracker) TakeDirty() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	d := t.dirty
	t.dirty = false
	return d
}

// Reset 清空已记录的流。已在 assembler 里的连接会在下次有数据时重新出现。
func (t *Tracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.streams = make(map[string]*entry)
	t.order = nil
	t.dirty = true
}

// register 在首个报文到达时建流。超过上限时返回空 id，
// 对应的 stream 会把后续数据丢弃而不是让内存无界增长。
func (t *Tracker) register(id, clientAddr, serverAddr string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.streams[id]; ok {
		return true
	}
	if len(t.streams) >= t.maxStreams {
		return false
	}
	stamp := now.Format(time.DateTime)
	t.streams[id] = &entry{
		summary: models.TCPStreamSummary{
			ID:         id,
			Date:       stamp,
			Updated:    stamp,
			ClientAddr: clientAddr,
			ServerAddr: serverAddr,
		},
		lastSeen: now,
	}
	t.order = append(t.order, id)
	t.dirty = true
	return true
}

// append 追加一段已重组的数据。skipped 是本段之前被跳过的字节数。
func (t *Tracker) append(id string, toServer bool, data []byte, skipped int, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e := t.streams[id]
	if e == nil {
		return
	}

	if skipped > 0 {
		e.summary.MissingBytes += int64(skipped)
	}
	if toServer {
		e.summary.ClientBytes += int64(len(data))
		e.client, e.clientTrunc = appendCapped(e.client, data, t.maxBytes, e.clientTrunc)
	} else {
		e.summary.ServerBytes += int64(len(data))
		e.server, e.serverTrunc = appendCapped(e.server, data, t.maxBytes, e.serverTrunc)
	}
	e.summary.Updated = now.Format(time.DateTime)
	e.lastSeen = now
	t.dirty = true
}

func (t *Tracker) markClosed(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if e := t.streams[id]; e != nil && !e.summary.Closed {
		e.summary.Closed = true
		t.dirty = true
	}
}

// appendCapped 追加到上限为止，超出的部分直接丢弃并标记截断。
func appendCapped(dst, data []byte, limit int, truncated bool) ([]byte, bool) {
	room := limit - len(dst)
	if room <= 0 {
		return dst, true
	}
	if len(data) > room {
		return append(dst, data[:room]...), true
	}
	return append(dst, data...), truncated
}

// context 携带抓包时间，reassembly 用它判断空闲超时
type context struct{ ci gopacket.CaptureInfo }

func (c context) GetCaptureInfo() gopacket.CaptureInfo { return c.ci }

type factory struct{ t *Tracker }

func (f factory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	clientAddr := fmt.Sprintf("%s:%s", netFlow.Src(), tcpFlow.Src())
	serverAddr := fmt.Sprintf("%s:%s", netFlow.Dst(), tcpFlow.Dst())
	id := clientAddr + "-" + serverAddr

	now := ac.GetCaptureInfo().Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	// 超过流数上限时仍要返回一个 Stream（接口要求），但让它丢弃全部数据
	tracked := f.t.register(id, clientAddr, serverAddr, now)
	return &stream{tracker: f.t, id: id, tracked: tracked}
}

type stream struct {
	tracker *Tracker
	id      string
	tracked bool
}

// Accept 不做 TCP 状态校验：抓包常从连接中途开始，
// 严格校验会把大量正常流量判为无效而看不到任何内容。
func (s *stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection,
	nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return s.tracked
}

func (s *stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	dir, _, _, skip := sg.Info()
	if length == 0 && skip <= 0 {
		return
	}

	// sg 会被复用，Fetch 返回的内容必须在本次调用内消费完
	data := sg.Fetch(length)
	now := ac.GetCaptureInfo().Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	// skip < 0 表示重叠而非丢失，不计入缺失字节
	if skip < 0 {
		skip = 0
	}
	s.tracker.append(s.id, dir == reassembly.TCPDirClientToServer, data, skip, now)
}

// ReassemblyComplete 返回 true 让连接从池中移除：
// 我们不做 FIN-ACK 之后的状态机分析，留着只是占内存。
func (s *stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	s.tracker.markClosed(s.id)
	return true
}

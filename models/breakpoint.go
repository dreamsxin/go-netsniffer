package models

import "net/http"

// BreakpointPhase 指明断点拦在请求还是响应阶段
type BreakpointPhase string

const (
	BreakpointPhaseRequest  BreakpointPhase = "request"
	BreakpointPhaseResponse BreakpointPhase = "response"
)

// BreakpointConfig 是断点的开关与匹配条件。
//
// 断点会真的把请求挂住等人处理，属于调试用途，默认关闭。
type BreakpointConfig struct {
	// Enabled 关闭时完全不拦截，连匹配都不做
	Enabled bool `json:"Enabled"`
	// URLRegex 匹配完整 URL，留空表示匹配全部。
	// 留空且开启会拦下所有流量，等于把网络挂死，界面上要提醒
	URLRegex string `json:"URLRegex"`
	// Method 限定请求方法，留空不限制
	Method string `json:"Method"`
	// OnRequest / OnResponse 分别控制两个阶段是否拦截
	OnRequest  bool `json:"OnRequest"`
	OnResponse bool `json:"OnResponse"`
	// TimeoutSeconds 是无人处理时自动放行的秒数。
	// 必须有兜底：否则忘了处理就等于把那条连接永久挂死
	TimeoutSeconds int `json:"TimeoutSeconds"`
}

// DefaultBreakpointConfig 默认关闭，且只拦请求阶段
func DefaultBreakpointConfig() BreakpointConfig {
	return BreakpointConfig{
		Enabled:        false,
		OnRequest:      true,
		OnResponse:     false,
		TimeoutSeconds: 60,
	}
}

// BreakpointHit 是一个正在等待处理的断点，推送给界面展示
type BreakpointHit struct {
	// ID 用于回传处理结果，与报文记录的 ID 一致
	ID    string          `json:"ID"`
	Phase BreakpointPhase `json:"Phase"`
	// Date 是命中时刻，便于判断已经挂了多久
	Date   string      `json:"Date"`
	Method string      `json:"Method"`
	URL    string      `json:"URL"`
	Header http.Header `json:"Header,omitempty"`
	Body   string      `json:"Body,omitempty"`
	// BodyBinary 为 true 时 Body 不是可读文本，界面应禁止编辑
	BodyBinary bool `json:"BodyBinary,omitempty"`
	// StatusCode 仅响应阶段有值
	StatusCode int `json:"StatusCode,omitempty"`
	// DeadlineSeconds 是剩余的自动放行秒数
	DeadlineSeconds int `json:"DeadlineSeconds"`
}

// BreakpointAction 是界面对断点的处置方式
type BreakpointAction string

const (
	// BreakpointResume 原样放行
	BreakpointResume BreakpointAction = "resume"
	// BreakpointModify 按回传内容改写后放行
	BreakpointModify BreakpointAction = "modify"
	// BreakpointAbort 中止该请求，直接返回错误给客户端
	BreakpointAbort BreakpointAction = "abort"
)

// BreakpointResolution 是界面回传的处理结果
type BreakpointResolution struct {
	ID     string           `json:"ID"`
	Action BreakpointAction `json:"Action"`
	// 以下字段仅在 Action 为 modify 时使用
	Method     string      `json:"Method,omitempty"`
	URL        string      `json:"URL,omitempty"`
	Header     http.Header `json:"Header,omitempty"`
	Body       string      `json:"Body,omitempty"`
	StatusCode int         `json:"StatusCode,omitempty"`
}

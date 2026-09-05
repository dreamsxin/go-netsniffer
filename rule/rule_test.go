package rule

import "testing"

func TestShouldMITMOrderMatters(t *testing.T) {
	// 全部解密，但排除微信
	s := New("*\n!weixin.qq.com\n")

	if !s.ShouldMITM("example.com") {
		t.Error("example.com 应解密")
	}
	if s.ShouldMITM("weixin.qq.com") {
		t.Error("weixin.qq.com 被否定规则排除，不应解密")
	}
	// 精确否定不应影响子域
	if !s.ShouldMITM("api.weixin.qq.com") {
		t.Error("精确规则不应波及子域")
	}
}

func TestShouldMITMWildcard(t *testing.T) {
	s := New("*.example.com")

	for _, h := range []string{"example.com", "api.example.com", "a.b.example.com"} {
		if !s.ShouldMITM(h) {
			t.Errorf("%s 应命中通配规则", h)
		}
	}
	for _, h := range []string{"notexample.com", "example.com.cn"} {
		if s.ShouldMITM(h) {
			t.Errorf("%s 不应命中通配规则", h)
		}
	}
}

func TestShouldMITMWildcardNegation(t *testing.T) {
	s := New("*\n!*.qq.com\nvideo.qq.com\n")

	if s.ShouldMITM("res.wx.qq.com") {
		t.Error("*.qq.com 被排除")
	}
	// 后面的精确规则覆盖前面的通配否定
	if !s.ShouldMITM("video.qq.com") {
		t.Error("后置精确规则应覆盖前置通配否定")
	}
}

func TestShouldMITMEmptyMeansNoDecrypt(t *testing.T) {
	s := New("# 只有注释\n\n")
	if s.ShouldMITM("example.com") {
		t.Error("无规则时不应解密")
	}
}

func TestShouldMITMNormalizesHost(t *testing.T) {
	s := New("example.com")

	for _, h := range []string{"example.com:443", "EXAMPLE.COM", "example.com.", " example.com "} {
		if !s.ShouldMITM(h) {
			t.Errorf("%q 归一化后应命中", h)
		}
	}
}

func TestShouldMITMIPv6(t *testing.T) {
	s := New("::1")

	for _, h := range []string{"[::1]:443", "::1"} {
		if !s.ShouldMITM(h) {
			t.Errorf("%q 应命中 IPv6 规则", h)
		}
	}
}

func TestLoadReplacesRules(t *testing.T) {
	s := New("*")
	if !s.ShouldMITM("example.com") {
		t.Fatal("初始规则应解密")
	}

	s.Load("!*")
	if s.ShouldMITM("example.com") {
		t.Error("热更新后不应再解密")
	}
	if s.Text() != "!*" {
		t.Errorf("Text() = %q", s.Text())
	}
}

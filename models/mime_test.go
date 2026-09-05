package models

import "testing"

func TestClassifyContentType(t *testing.T) {
	cases := []struct {
		contentType string
		url         string
		wantKind    ResourceType
		wantSuffix  string
	}{
		{"text/html; charset=utf-8", "http://a.com/", ResourceTypeText, ".html"},
		{"application/json", "http://a.com/api", ResourceTypeText, ".json"},
		{"image/jpeg", "http://a.com/x", ResourceTypeImage, ".jpg"},
		{"image/webp", "http://a.com/x", ResourceTypeImage, ".webp"},
		{"video/mp4", "http://a.com/v", ResourceTypeVideo, ".mp4"},
		{"audio/mpeg", "http://a.com/a", ResourceTypeAudio, ".mp3"},
		{"application/pdf", "http://a.com/d", ResourceTypeDocument, ".pdf"},
	}

	for _, c := range cases {
		kind, suffix := ClassifyContentType(c.contentType, c.url)
		if kind != c.wantKind || suffix != c.wantSuffix {
			t.Errorf("ClassifyContentType(%q) = (%s, %s), want (%s, %s)",
				c.contentType, kind, suffix, c.wantKind, c.wantSuffix)
		}
	}
}

// octet-stream 这类无意义的 MIME 要靠 URL 扩展名兜底
func TestClassifyContentTypeFallsBackToURL(t *testing.T) {
	kind, suffix := ClassifyContentType("application/octet-stream", "https://a.com/v/movie.mp4?token=1")
	if kind != ResourceTypeVideo {
		t.Errorf("kind = %s, want video", kind)
	}
	if suffix != ".mp4" {
		t.Errorf("suffix = %s, want .mp4", suffix)
	}
}

func TestClassifyContentTypeUnknown(t *testing.T) {
	kind, suffix := ClassifyContentType("", "https://a.com/some/path")
	if kind != ResourceTypeOther {
		t.Errorf("kind = %s, want other", kind)
	}
	if suffix != ".bin" {
		t.Errorf("suffix = %s, want .bin", suffix)
	}
}

func TestExtFromURLIgnoresQueryAndFragment(t *testing.T) {
	if got := extFromURL("https://a.com/p/x.PNG?a=1#f"); got != ".png" {
		t.Errorf("extFromURL = %q, want .png", got)
	}
	// 路径片段被误当成后缀的情况要排除
	if got := extFromURL("https://a.com/v1.verylongsegment/x"); got != "" {
		t.Errorf("extFromURL = %q, want empty", got)
	}
	if got := extFromURL("https://a.com/path"); got != "" {
		t.Errorf("extFromURL = %q, want empty", got)
	}
	// 域名里的点不能被当成扩展名
	if got := extFromURL("https://a.com/"); got != "" {
		t.Errorf("extFromURL = %q, want empty", got)
	}
	if got := extFromURL("https://a.com"); got != "" {
		t.Errorf("extFromURL = %q, want empty", got)
	}
}

func TestFileNameFromURL(t *testing.T) {
	cases := []struct {
		url    string
		suffix string
		want   string
	}{
		{"https://a.com/img/photo.jpeg?x=1", ".jpg", "photo.jpg"},
		{"https://a.com/", ".html", "download.html"},
		{"https://a.com/a/b/c", ".bin", "c.bin"},
	}
	for _, c := range cases {
		if got := FileNameFromURL(c.url, c.suffix); got != c.want {
			t.Errorf("FileNameFromURL(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

// Windows 文件名不允许的字符必须被替换，否则保存会直接失败
func TestFileNameFromURLSanitizes(t *testing.T) {
	got := FileNameFromURL("https://a.com/a<b>c:d.png", ".png")
	for _, ch := range `<>:"/\|?*` {
		if containsRune(got, ch) {
			t.Errorf("文件名 %q 仍包含非法字符 %q", got, ch)
		}
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

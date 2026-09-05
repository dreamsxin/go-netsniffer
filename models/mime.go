package models

import (
	"mime"
	"net/url"
	"path"
	"strings"
)

// ResourceType 是按 Content-Type 归纳出的资源大类，决定界面用哪种方式预览。
type ResourceType string

const (
	ResourceTypeText     ResourceType = "text"
	ResourceTypeImage    ResourceType = "image"
	ResourceTypeAudio    ResourceType = "audio"
	ResourceTypeVideo    ResourceType = "video"
	ResourceTypeDocument ResourceType = "document"
	ResourceTypeOther    ResourceType = "other"
)

// mimeSuffix 把 MIME 映射为文件后缀。只列常见类型，
// 未命中的走前缀归类，再退回按 URL 扩展名推断。
var mimeSuffix = map[string]string{
	// 文本
	"text/html":                       ".html",
	"text/plain":                      ".txt",
	"text/css":                        ".css",
	"text/csv":                        ".csv",
	"text/javascript":                 ".js",
	"application/javascript":          ".js",
	"application/x-javascript":        ".js",
	"application/json":                ".json",
	"application/xml":                 ".xml",
	"text/xml":                        ".xml",
	"application/x-www-form-urlencoded": ".txt",

	// 图片
	"image/jpeg":    ".jpg",
	"image/png":     ".png",
	"image/gif":     ".gif",
	"image/webp":    ".webp",
	"image/avif":    ".avif",
	"image/bmp":     ".bmp",
	"image/svg+xml": ".svg",
	"image/x-icon":  ".ico",
	"image/vnd.microsoft.icon": ".ico",
	"image/tiff":    ".tiff",
	"image/heic":    ".heic",

	// 音频
	"audio/mpeg":  ".mp3",
	"audio/mp4":   ".m4a",
	"audio/aac":   ".aac",
	"audio/ogg":   ".ogg",
	"audio/wav":   ".wav",
	"audio/x-wav": ".wav",
	"audio/webm":  ".weba",
	"audio/flac":  ".flac",

	// 视频
	"video/mp4":                    ".mp4",
	"video/webm":                   ".webm",
	"video/ogg":                    ".ogv",
	"video/quicktime":              ".mov",
	"video/x-msvideo":              ".avi",
	"video/x-matroska":             ".mkv",
	"video/mp2t":                   ".ts",
	"application/vnd.apple.mpegurl": ".m3u8",
	"application/x-mpegurl":         ".m3u8",

	// 文档与压缩包
	"application/pdf":  ".pdf",
	"application/zip":  ".zip",
	"application/gzip": ".gz",
	"application/x-7z-compressed": ".7z",
	"application/x-rar-compressed": ".rar",
	"application/msword": ".doc",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
	"application/vnd.ms-excel": ".xls",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
	"application/vnd.ms-powerpoint": ".ppt",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",

	// 字体
	"font/woff":  ".woff",
	"font/woff2": ".woff2",
	"font/ttf":   ".ttf",
	"font/otf":   ".otf",
}

// documentMIME 是需要归入"文档"大类的类型
var documentMIME = map[string]bool{
	"application/pdf":              true,
	"application/zip":              true,
	"application/gzip":             true,
	"application/x-7z-compressed":  true,
	"application/x-rar-compressed": true,
	"application/msword":           true,
	"application/vnd.ms-excel":     true,
	"application/vnd.ms-powerpoint": true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
}

// ClassifyContentType 根据 Content-Type 与 URL 推断资源大类与文件后缀。
// contentType 可带参数（如 "text/html; charset=utf-8"）。
func ClassifyContentType(contentType, rawURL string) (ResourceType, string) {
	base := baseMIME(contentType)
	suffix := mimeSuffix[base]

	kind := ResourceTypeOther
	switch {
	case documentMIME[base]:
		kind = ResourceTypeDocument
	case strings.HasPrefix(base, "image/"):
		kind = ResourceTypeImage
	case strings.HasPrefix(base, "audio/"):
		kind = ResourceTypeAudio
	case strings.HasPrefix(base, "video/"):
		kind = ResourceTypeVideo
	case isTextualMIME(base):
		kind = ResourceTypeText
	}

	// MIME 不可靠时（常见的 application/octet-stream）用 URL 扩展名兜底
	if suffix == "" || kind == ResourceTypeOther {
		if ext := extFromURL(rawURL); ext != "" {
			if suffix == "" {
				suffix = ext
			}
			if kind == ResourceTypeOther {
				kind = kindFromExt(ext)
			}
		}
	}
	if suffix == "" {
		suffix = ".bin"
	}
	return kind, suffix
}

func baseMIME(contentType string) string {
	if contentType == "" {
		return ""
	}
	if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
		return parsed
	}
	// 解析失败时退化为取分号前的部分
	return strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
}

func isTextualMIME(base string) bool {
	return strings.HasPrefix(base, "text/") ||
		strings.Contains(base, "json") ||
		strings.Contains(base, "xml") ||
		strings.Contains(base, "javascript") ||
		base == "application/x-www-form-urlencoded"
}

// urlPath 取出 URL 的路径部分。
// 必须先解析再取 Base：直接对整个 URL 调 path.Base，
// "https://a.com/" 会得到 "a.com"，扩展名被误判成 ".com"。
func urlPath(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		return u.Path
	}
	// 解析失败时退化为手工去掉查询串与片段
	p := rawURL
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	// 没有 scheme 的相对路径直接当作路径使用
	if !strings.Contains(p, "://") {
		return p
	}
	return ""
}

// extFromURL 取路径部分的扩展名，忽略查询串与片段。
func extFromURL(rawURL string) string {
	p := urlPath(rawURL)
	if p == "" {
		return ""
	}
	ext := strings.ToLower(path.Ext(path.Base(p)))
	// 扩展名过长基本是把路径片段误当成了后缀
	if len(ext) < 2 || len(ext) > 6 {
		return ""
	}
	return ext
}

var extKind = map[string]ResourceType{
	".jpg": ResourceTypeImage, ".jpeg": ResourceTypeImage, ".png": ResourceTypeImage,
	".gif": ResourceTypeImage, ".webp": ResourceTypeImage, ".avif": ResourceTypeImage,
	".bmp": ResourceTypeImage, ".svg": ResourceTypeImage, ".ico": ResourceTypeImage,
	".mp3": ResourceTypeAudio, ".m4a": ResourceTypeAudio, ".aac": ResourceTypeAudio,
	".ogg": ResourceTypeAudio, ".wav": ResourceTypeAudio, ".flac": ResourceTypeAudio,
	".mp4": ResourceTypeVideo, ".webm": ResourceTypeVideo, ".mov": ResourceTypeVideo,
	".avi": ResourceTypeVideo, ".mkv": ResourceTypeVideo, ".ts": ResourceTypeVideo,
	".m3u8": ResourceTypeVideo,
	".pdf":  ResourceTypeDocument, ".zip": ResourceTypeDocument, ".gz": ResourceTypeDocument,
	".7z": ResourceTypeDocument, ".rar": ResourceTypeDocument,
	".doc": ResourceTypeDocument, ".docx": ResourceTypeDocument,
	".xls": ResourceTypeDocument, ".xlsx": ResourceTypeDocument,
	".ppt": ResourceTypeDocument, ".pptx": ResourceTypeDocument,
	".html": ResourceTypeText, ".htm": ResourceTypeText, ".css": ResourceTypeText,
	".js": ResourceTypeText, ".json": ResourceTypeText, ".xml": ResourceTypeText,
	".txt": ResourceTypeText, ".csv": ResourceTypeText,
}

func kindFromExt(ext string) ResourceType {
	if k, ok := extKind[ext]; ok {
		return k
	}
	return ResourceTypeOther
}

// FileNameFromURL 根据 URL 与后缀推断一个用于保存的文件名。
func FileNameFromURL(rawURL, suffix string) string {
	name := path.Base(urlPath(rawURL))
	if name == "" || name == "." || name == "/" {
		name = "download"
	}
	// 去掉已有的扩展名再统一补上推断出的后缀
	if ext := path.Ext(name); ext != "" {
		name = strings.TrimSuffix(name, ext)
	}
	if name == "" {
		name = "download"
	}
	return sanitizeFileName(name) + suffix
}

// sanitizeFileName 剔除 Windows 文件名不允许的字符
func sanitizeFileName(name string) string {
	replacer := strings.NewReplacer(
		"<", "_", ">", "_", ":", "_", `"`, "_",
		"/", "_", `\`, "_", "|", "_", "?", "_", "*", "_",
	)
	name = replacer.Replace(name)
	name = strings.TrimSpace(name)
	if len(name) > 80 {
		name = name[:80]
	}
	if name == "" {
		return "download"
	}
	return name
}

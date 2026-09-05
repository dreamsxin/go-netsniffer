package models

import "testing"

func TestNormalizeFillsInvalidValues(t *testing.T) {
	cfg := Config{}
	cfg.HTTP.Status = 2
	cfg.IP.Status = 2
	cfg.Normalize()

	d := DefaultConfig()
	if cfg.HTTP.Port != d.HTTP.Port {
		t.Errorf("Port = %d, want %d", cfg.HTTP.Port, d.HTTP.Port)
	}
	if cfg.HTTP.MaxBodySize != d.HTTP.MaxBodySize {
		t.Errorf("MaxBodySize = %d, want %d", cfg.HTTP.MaxBodySize, d.HTTP.MaxBodySize)
	}
	if cfg.IP.Snaplen != d.IP.Snaplen {
		t.Errorf("Snaplen = %d, want %d", cfg.IP.Snaplen, d.IP.Snaplen)
	}
	if cfg.IP.Timeout != d.IP.Timeout {
		t.Errorf("Timeout = %d, want %d", cfg.IP.Timeout, d.IP.Timeout)
	}
	if cfg.HTTP.Status != 0 || cfg.IP.Status != 0 {
		t.Errorf("运行状态应被重置为未启动，得到 HTTP=%d IP=%d", cfg.HTTP.Status, cfg.IP.Status)
	}
}

func TestNormalizeKeepsValidValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HTTP.Port = 8888
	cfg.HTTP.MaxBodySize = 4096
	cfg.IP.Snaplen = 512
	cfg.Normalize()

	if cfg.HTTP.Port != 8888 || cfg.HTTP.MaxBodySize != 4096 || cfg.IP.Snaplen != 512 {
		t.Errorf("合法配置不应被覆盖: %+v", cfg)
	}
}

func TestNormalizeRejectsOutOfRangePort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HTTP.Port = 70000
	cfg.Normalize()

	if cfg.HTTP.Port != DefaultConfig().HTTP.Port {
		t.Errorf("越界端口应回退到默认值，得到 %d", cfg.HTTP.Port)
	}
}

package models

type Config struct {
	Status      int // 0 未启动 1 启动中 2 已启动
	Port        int
	AutoProxy   bool
	SaveLogFile bool
	Filter      bool
	FilterHost  string
}

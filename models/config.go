package models

type HTTP struct {
	Status      int // 0 未启动 1 启动中 2 已启动
	Port        int
	AutoProxy   bool
	SaveLogFile bool
	Filter      bool
	FilterHost  string
}

type TCP struct {
	Status  int    // 0 未启动 1 启动中 2 已启动
	Device  string // 网络设备的名称，如eth0,也可以填充pcap.FindAllDevs()返回的设备的Name
	Snaplen int32  // 每个数据包读取的最大长度，如果设置成1024，那么每次读取的数据包最大长度为1024字节
	Promisc bool   // 是否将网口设置为混杂模式，如果设置成true，那么网卡会将所有的数据包都抓到
	Timeout int64  // 设置抓到包返回的超时时间，单位为毫秒
}

type Config struct {
	HTTP HTTP
	TCP  TCP
}

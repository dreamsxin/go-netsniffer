# README

一个 http/https 协议调试代理工具。

## 功能

抓包与查看
- HTTPS 解密按域名规则控制，未列入的域名只做隧道转发，不会破坏做了证书固定的客户端
- 请求与响应配对展示，按内容类型分别预览，图片/音视频可内联播放
- 显示过滤：关键字（空格分隔多词、`-词` 排除）、方式、状态码段、资源类型，只影响视图不丢记录
- 导出 HAR、复制为 cURL、下载资源、写入 pcap

调试工具（默认全部关闭）
- 改包：按 JSON 规则改写请求与响应的头、正文、状态码
- 映射：Map Local 用本地文件充当响应，Map Remote 把请求转到另一个地址
- 断点：命中后真的挂住请求，等界面处理后放行
- 弱网模拟：限制上下行带宽并叠加延迟，带预设档位
- WebSocket 帧解析：旁路观察双向帧
- TCP 流重组：按序列号拼回双向字节流，可跟随流查看

## 平台支持


| 能力 | Windows | macOS | Linux |
| --- | --- | --- | --- |
| HTTP/HTTPS 抓包与解密 | 已验证 | 未验证 | 未验证 |
| 系统代理自动设置 | 已验证 | 未验证（networksetup） | 未验证（gsettings，仅 GNOME） |
| 根证书安装 | 已验证 | 未验证（security 钥匙串） | 未验证（需 root） |
| IP 层抓包 | 需 Npcap | 需 libpcap | 需 libpcap |

macOS 与 Linux 的系统代理、证书安装代码已补齐并能通过编译，但**尚未在真机上验证**，
遇到问题请手动在系统设置中确认代理与证书状态。

IP 抓包依赖 libpcap 绑定（cgo），因此：

- Windows 需安装 [Npcap](https://npcap.com/)
- macOS/Linux 需安装 libpcap 开发包（如 `apt install libpcap-dev`）并以 `CGO_ENABLED=1` 本机编译
- **无法交叉编译**，这是 libpcap 绑定的固有限制

Firefox 使用独立证书库，不读系统证书存储。用户级安装证书后，
需在 设置-隐私与安全-证书 中手工导入数据目录下的 `rootcrt.pem`。

## 调试

```shell
wails dev
```

## 构建

必须使用 `wails build`。直接 `go build` 缺少 `desktop,production` 构建标签，
生成的程序启动时只会弹提示框然后退出。

```shell
wails build
```


## 发布

```shell
#scoop bucket add extras
#scoop install nsis
wails build -nsis
```

## 截图

![screenshot-3](https://github.com/dreamsxin/go-netsniffer/blob/main/screenshot/screenshot-03.png?raw=true)
![screenshot-4](https://github.com/dreamsxin/go-netsniffer/blob/main/screenshot/screenshot-04.png?raw=true)

## 开源协议

[BSD 3-Clause](LICENSE)

主要依赖同为宽松协议：goproxy 与 gopacket 为 BSD-3-Clause，Wails、Vue、Element Plus 为 MIT。

Donation
--------

* [捐贈（Donation）](https://github.com/dreamsxin/cphalcon7/blob/master/DONATE.md)

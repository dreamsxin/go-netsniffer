# README

一个 http/https 协议调试代理工具。

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

Donation
--------

* [捐贈（Donation）](https://github.com/dreamsxin/cphalcon7/blob/master/DONATE.md)

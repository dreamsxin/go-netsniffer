package models

type Address struct {
	IP        string
	Netmask   string
	Broadaddr string
	P2P       string
}

type Device struct {
	Name        string
	Description string
	Flags       uint32
	Addresses   []Address
}

package models

type Config struct {
	Status      int
	Port        int
	AutoProxy   bool
	SaveLogFile bool
	Filter      bool
	FilterHost  string
}

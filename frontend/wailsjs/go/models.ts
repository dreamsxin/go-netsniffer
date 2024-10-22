export namespace events {
	
	export class Event {
	    Type: number;
	    Code: number;
	    Message: string;
	
	    static createFrom(source: any = {}) {
	        return new Event(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Type = source["Type"];
	        this.Code = source["Code"];
	        this.Message = source["Message"];
	    }
	}

}

export namespace models {
	
	export class Address {
	    IP: string;
	    Netmask: string;
	    Broadaddr: string;
	    P2P: string;
	
	    static createFrom(source: any = {}) {
	        return new Address(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.IP = source["IP"];
	        this.Netmask = source["Netmask"];
	        this.Broadaddr = source["Broadaddr"];
	        this.P2P = source["P2P"];
	    }
	}
	export class TCP {
	    Status: number;
	    Device: string;
	    Snaplen: number;
	    Promisc: boolean;
	    Timeout: number;
	
	    static createFrom(source: any = {}) {
	        return new TCP(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Status = source["Status"];
	        this.Device = source["Device"];
	        this.Snaplen = source["Snaplen"];
	        this.Promisc = source["Promisc"];
	        this.Timeout = source["Timeout"];
	    }
	}
	export class HTTP {
	    Status: number;
	    Port: number;
	    AutoProxy: boolean;
	    SaveLogFile: boolean;
	    Filter: boolean;
	    FilterHost: string;
	
	    static createFrom(source: any = {}) {
	        return new HTTP(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Status = source["Status"];
	        this.Port = source["Port"];
	        this.AutoProxy = source["AutoProxy"];
	        this.SaveLogFile = source["SaveLogFile"];
	        this.Filter = source["Filter"];
	        this.FilterHost = source["FilterHost"];
	    }
	}
	export class Config {
	    HTTP: HTTP;
	    TCP: TCP;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.HTTP = this.convertValues(source["HTTP"], HTTP);
	        this.TCP = this.convertValues(source["TCP"], TCP);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Device {
	    Name: string;
	    Description: string;
	    Flags: number;
	    Addresses: Address[];
	
	    static createFrom(source: any = {}) {
	        return new Device(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Name = source["Name"];
	        this.Description = source["Description"];
	        this.Flags = source["Flags"];
	        this.Addresses = this.convertValues(source["Addresses"], Address);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}


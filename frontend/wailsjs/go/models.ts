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
	export class CertStatus {
	    Generated: boolean;
	    TrustedScopes: string[];
	    CertPath: string;
	    NotAfter: string;
	
	    static createFrom(source: any = {}) {
	        return new CertStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Generated = source["Generated"];
	        this.TrustedScopes = source["TrustedScopes"];
	        this.CertPath = source["CertPath"];
	        this.NotAfter = source["NotAfter"];
	    }
	}
	export class IP {
	    Status: number;
	    Device: string;
	    Snaplen: number;
	    Promisc: boolean;
	    Timeout: number;
	    Filter: string;
	    SavePcapFile: boolean;
	
	    static createFrom(source: any = {}) {
	        return new IP(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Status = source["Status"];
	        this.Device = source["Device"];
	        this.Snaplen = source["Snaplen"];
	        this.Promisc = source["Promisc"];
	        this.Timeout = source["Timeout"];
	        this.Filter = source["Filter"];
	        this.SavePcapFile = source["SavePcapFile"];
	    }
	}
	export class HTTP {
	    Status: number;
	    Port: number;
	    AutoProxy: boolean;
	    SaveLogFile: boolean;
	    Filter: boolean;
	    FilterHost: string;
	    ResourceTypes: string[];
	    MaxBodySize: number;
	    UpstreamProxy: string;
	    Rule: string;
	    AllowHTTP2: boolean;
	    DownloadDir: string;
	
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
	        this.ResourceTypes = source["ResourceTypes"];
	        this.MaxBodySize = source["MaxBodySize"];
	        this.UpstreamProxy = source["UpstreamProxy"];
	        this.Rule = source["Rule"];
	        this.AllowHTTP2 = source["AllowHTTP2"];
	        this.DownloadDir = source["DownloadDir"];
	    }
	}
	export class Config {
	    HTTP: HTTP;
	    IP: IP;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.HTTP = this.convertValues(source["HTTP"], HTTP);
	        this.IP = this.convertValues(source["IP"], IP);
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
	
	export class HTTPPacket {
	    Date: string;
	    ID?: string;
	    HTTPPacketType?: number;
	    Proto?: string;
	    ProtoMajor?: number;
	    ProtoMinor?: number;
	    Method?: string;
	    Host?: string;
	    Path?: string;
	    URL?: string;
	    Header?: Record<string, Array<string>>;
	    Body?: string;
	    BodyTruncated?: boolean;
	    Status?: string;
	    StatusCode?: number;
	    ContentType?: string;
	    ContentLength?: number;
	    Duration?: number;
	    ResourceType?: string;
	    Suffix?: string;
	    RequestHeader?: Record<string, Array<string>>;
	
	    static createFrom(source: any = {}) {
	        return new HTTPPacket(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Date = source["Date"];
	        this.ID = source["ID"];
	        this.HTTPPacketType = source["HTTPPacketType"];
	        this.Proto = source["Proto"];
	        this.ProtoMajor = source["ProtoMajor"];
	        this.ProtoMinor = source["ProtoMinor"];
	        this.Method = source["Method"];
	        this.Host = source["Host"];
	        this.Path = source["Path"];
	        this.URL = source["URL"];
	        this.Header = source["Header"];
	        this.Body = source["Body"];
	        this.BodyTruncated = source["BodyTruncated"];
	        this.Status = source["Status"];
	        this.StatusCode = source["StatusCode"];
	        this.ContentType = source["ContentType"];
	        this.ContentLength = source["ContentLength"];
	        this.Duration = source["Duration"];
	        this.ResourceType = source["ResourceType"];
	        this.Suffix = source["Suffix"];
	        this.RequestHeader = source["RequestHeader"];
	    }
	}
	
	export class ReplayRequest {
	    Method: string;
	    URL: string;
	    Header?: Record<string, Array<string>>;
	    Body?: string;
	
	    static createFrom(source: any = {}) {
	        return new ReplayRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Method = source["Method"];
	        this.URL = source["URL"];
	        this.Header = source["Header"];
	        this.Body = source["Body"];
	    }
	}

}


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
	export class AppStatus {
	    HTTPStatus: number;
	    IPStatus: number;
	    Port: number;
	    AutoProxy: boolean;
	    Cert: CertStatus;
	    RewriteRuleCount: number;
	    MapRuleCount: number;
	    BreakpointEnabled: boolean;
	    PendingBreakpoints: number;
	    ThrottleActive: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AppStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.HTTPStatus = source["HTTPStatus"];
	        this.IPStatus = source["IPStatus"];
	        this.Port = source["Port"];
	        this.AutoProxy = source["AutoProxy"];
	        this.Cert = this.convertValues(source["Cert"], CertStatus);
	        this.RewriteRuleCount = source["RewriteRuleCount"];
	        this.MapRuleCount = source["MapRuleCount"];
	        this.BreakpointEnabled = source["BreakpointEnabled"];
	        this.PendingBreakpoints = source["PendingBreakpoints"];
	        this.ThrottleActive = source["ThrottleActive"];
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
	export class BreakpointConfig {
	    Enabled: boolean;
	    URLRegex: string;
	    Method: string;
	    OnRequest: boolean;
	    OnResponse: boolean;
	    TimeoutSeconds: number;
	
	    static createFrom(source: any = {}) {
	        return new BreakpointConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Enabled = source["Enabled"];
	        this.URLRegex = source["URLRegex"];
	        this.Method = source["Method"];
	        this.OnRequest = source["OnRequest"];
	        this.OnResponse = source["OnResponse"];
	        this.TimeoutSeconds = source["TimeoutSeconds"];
	    }
	}
	export class BreakpointHit {
	    ID: string;
	    Phase: string;
	    Date: string;
	    Method: string;
	    URL: string;
	    Header?: Record<string, Array<string>>;
	    Body?: string;
	    BodyBinary?: boolean;
	    StatusCode?: number;
	    DeadlineSeconds: number;
	
	    static createFrom(source: any = {}) {
	        return new BreakpointHit(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.Phase = source["Phase"];
	        this.Date = source["Date"];
	        this.Method = source["Method"];
	        this.URL = source["URL"];
	        this.Header = source["Header"];
	        this.Body = source["Body"];
	        this.BodyBinary = source["BodyBinary"];
	        this.StatusCode = source["StatusCode"];
	        this.DeadlineSeconds = source["DeadlineSeconds"];
	    }
	}
	export class BreakpointResolution {
	    ID: string;
	    Action: string;
	    Method?: string;
	    URL?: string;
	    Header?: Record<string, Array<string>>;
	    Body?: string;
	    StatusCode?: number;
	
	    static createFrom(source: any = {}) {
	        return new BreakpointResolution(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.Action = source["Action"];
	        this.Method = source["Method"];
	        this.URL = source["URL"];
	        this.Header = source["Header"];
	        this.Body = source["Body"];
	        this.StatusCode = source["StatusCode"];
	    }
	}
	
	export class TCPStreamConfig {
	    Enabled: boolean;
	    MaxStreamBytes: number;
	    MaxStreams: number;
	    IdleSeconds: number;
	
	    static createFrom(source: any = {}) {
	        return new TCPStreamConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Enabled = source["Enabled"];
	        this.MaxStreamBytes = source["MaxStreamBytes"];
	        this.MaxStreams = source["MaxStreams"];
	        this.IdleSeconds = source["IdleSeconds"];
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
	    TCPStream: TCPStreamConfig;
	
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
	        this.TCPStream = this.convertValues(source["TCPStream"], TCPStreamConfig);
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
	export class ThrottleConfig {
	    Enabled: boolean;
	    DownKbps: number;
	    UpKbps: number;
	    LatencyMs: number;
	    URLRegex?: string;
	
	    static createFrom(source: any = {}) {
	        return new ThrottleConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Enabled = source["Enabled"];
	        this.DownKbps = source["DownKbps"];
	        this.UpKbps = source["UpKbps"];
	        this.LatencyMs = source["LatencyMs"];
	        this.URLRegex = source["URLRegex"];
	    }
	}
	export class WebSocketConfig {
	    Enabled: boolean;
	    MaxPayloadBytes: number;
	
	    static createFrom(source: any = {}) {
	        return new WebSocketConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Enabled = source["Enabled"];
	        this.MaxPayloadBytes = source["MaxPayloadBytes"];
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
	    RewriteRules: string;
	    MapRules: string;
	    Breakpoint: BreakpointConfig;
	    WebSocket: WebSocketConfig;
	    Throttle: ThrottleConfig;
	
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
	        this.RewriteRules = source["RewriteRules"];
	        this.MapRules = source["MapRules"];
	        this.Breakpoint = this.convertValues(source["Breakpoint"], BreakpointConfig);
	        this.WebSocket = this.convertValues(source["WebSocket"], WebSocketConfig);
	        this.Throttle = this.convertValues(source["Throttle"], ThrottleConfig);
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
	    Rewritten?: string[];
	
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
	        this.Rewritten = source["Rewritten"];
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
	
	export class TCPStreamDetail {
	    ID: string;
	    Date: string;
	    Updated: string;
	    ClientAddr: string;
	    ServerAddr: string;
	    ClientBytes: number;
	    ServerBytes: number;
	    MissingBytes: number;
	    Closed: boolean;
	    ClientPayload?: number[];
	    ServerPayload?: number[];
	    ClientTruncated?: boolean;
	    ServerTruncated?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new TCPStreamDetail(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.Date = source["Date"];
	        this.Updated = source["Updated"];
	        this.ClientAddr = source["ClientAddr"];
	        this.ServerAddr = source["ServerAddr"];
	        this.ClientBytes = source["ClientBytes"];
	        this.ServerBytes = source["ServerBytes"];
	        this.MissingBytes = source["MissingBytes"];
	        this.Closed = source["Closed"];
	        this.ClientPayload = source["ClientPayload"];
	        this.ServerPayload = source["ServerPayload"];
	        this.ClientTruncated = source["ClientTruncated"];
	        this.ServerTruncated = source["ServerTruncated"];
	    }
	}
	export class TCPStreamSummary {
	    ID: string;
	    Date: string;
	    Updated: string;
	    ClientAddr: string;
	    ServerAddr: string;
	    ClientBytes: number;
	    ServerBytes: number;
	    MissingBytes: number;
	    Closed: boolean;
	
	    static createFrom(source: any = {}) {
	        return new TCPStreamSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.Date = source["Date"];
	        this.Updated = source["Updated"];
	        this.ClientAddr = source["ClientAddr"];
	        this.ServerAddr = source["ServerAddr"];
	        this.ClientBytes = source["ClientBytes"];
	        this.ServerBytes = source["ServerBytes"];
	        this.MissingBytes = source["MissingBytes"];
	        this.Closed = source["Closed"];
	    }
	}
	

}


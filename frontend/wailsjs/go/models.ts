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
	
	export class Config {
	    Status: number;
	    Port: number;
	    AutoProxy: boolean;
	    SaveLogFile: boolean;
	    Filter: boolean;
	    FilterHost: string;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
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

}


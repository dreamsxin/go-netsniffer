export namespace models {
	
	export class Config {
	    Port: number;
	    AutoProxy: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Port = source["Port"];
	        this.AutoProxy = source["AutoProxy"];
	    }
	}

}


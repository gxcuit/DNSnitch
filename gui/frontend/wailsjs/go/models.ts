export namespace main {
	
	export class GUIError {
	    kind: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new GUIError(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.message = source["message"];
	    }
	}
	export class GUIResult {
	    result?: report.CheckResult;
	    error?: GUIError;
	
	    static createFrom(source: any = {}) {
	        return new GUIResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.result = this.convertValues(source["result"], report.CheckResult);
	        this.error = this.convertValues(source["error"], GUIError);
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
	export class SourceFile {
	    path: string;
	    lines: string[];
	
	    static createFrom(source: any = {}) {
	        return new SourceFile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.lines = source["lines"];
	    }
	}

}

export namespace model {
	
	export class ResolverInfo {
	    level: string;
	    source: string;
	    policy_key?: string;
	
	    static createFrom(source: any = {}) {
	        return new ResolverInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.level = source["level"];
	        this.source = source["source"];
	        this.policy_key = source["policy_key"];
	    }
	}
	export class Location {
	    file: string;
	    line: number;
	    path?: string;
	    text?: string;
	    role?: string;
	    resolver?: ResolverInfo;
	
	    static createFrom(source: any = {}) {
	        return new Location(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.file = source["file"];
	        this.line = source["line"];
	        this.path = source["path"];
	        this.text = source["text"];
	        this.role = source["role"];
	        this.resolver = this.convertValues(source["resolver"], ResolverInfo);
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

export namespace report {
	
	export class Summary {
	    error: number;
	    high: number;
	    medium: number;
	    low: number;
	    info: number;
	
	    static createFrom(source: any = {}) {
	        return new Summary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.error = source["error"];
	        this.high = source["high"];
	        this.medium = source["medium"];
	        this.low = source["low"];
	        this.info = source["info"];
	    }
	}
	export class FindingView {
	    id: string;
	    severity: string;
	    message: string;
	    locations: model.Location[];
	    fix: string;
	    notes: string[];
	
	    static createFrom(source: any = {}) {
	        return new FindingView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.severity = source["severity"];
	        this.message = source["message"];
	        this.locations = this.convertValues(source["locations"], model.Location);
	        this.fix = source["fix"];
	        this.notes = source["notes"];
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
	export class CheckResult {
	    file: string;
	    findings: FindingView[];
	    summary: Summary;
	
	    static createFrom(source: any = {}) {
	        return new CheckResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.file = source["file"];
	        this.findings = this.convertValues(source["findings"], FindingView);
	        this.summary = this.convertValues(source["summary"], Summary);
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
	
	export class FixStep {
	    text: string;
	    command?: string;
	
	    static createFrom(source: any = {}) {
	        return new FixStep(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.text = source["text"];
	        this.command = source["command"];
	    }
	}
	export class Labels {
	    severity: Record<string, string>;
	    role: Record<string, string>;
	    level: Record<string, string>;
	    resolver_source: Record<string, string>;
	    text: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new Labels(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severity = source["severity"];
	        this.role = source["role"];
	        this.level = source["level"];
	        this.resolver_source = source["resolver_source"];
	        this.text = source["text"];
	    }
	}
	export class StatusItem {
	    title: string;
	    state: string;
	    label: string;
	    reason: string;
	    detail: string[];
	    note: string;
	
	    static createFrom(source: any = {}) {
	        return new StatusItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.state = source["state"];
	        this.label = source["label"];
	        this.reason = source["reason"];
	        this.detail = source["detail"];
	        this.note = source["note"];
	    }
	}
	export class StatusView {
	    os: string;
	    smart: StatusItem;
	    tun: StatusItem;
	    risk: boolean;
	    conclusion_code: string;
	    conclusion: string;
	    fix: FixStep[];
	
	    static createFrom(source: any = {}) {
	        return new StatusView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.os = source["os"];
	        this.smart = this.convertValues(source["smart"], StatusItem);
	        this.tun = this.convertValues(source["tun"], StatusItem);
	        this.risk = source["risk"];
	        this.conclusion_code = source["conclusion_code"];
	        this.conclusion = source["conclusion"];
	        this.fix = this.convertValues(source["fix"], FixStep);
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


export namespace fix {
	
	export class DiffLine {
	    op: string;
	    text: string;
	    no_newline?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new DiffLine(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.op = source["op"];
	        this.text = source["text"];
	        this.no_newline = source["no_newline"];
	    }
	}
	export class Edit {
	    id: string;
	    line: number;
	    path: string;
	    before: string;
	    after: string;
	
	    static createFrom(source: any = {}) {
	        return new Edit(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.line = source["line"];
	        this.path = source["path"];
	        this.before = source["before"];
	        this.after = source["after"];
	    }
	}
	export class Hunk {
	    old_start: number;
	    old_lines: number;
	    new_start: number;
	    new_lines: number;
	    lines: DiffLine[];
	
	    static createFrom(source: any = {}) {
	        return new Hunk(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.old_start = source["old_start"];
	        this.old_lines = source["old_lines"];
	        this.new_start = source["new_start"];
	        this.new_lines = source["new_lines"];
	        this.lines = this.convertValues(source["lines"], DiffLine);
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
	export class GUIFixResult {
	    result?: report.FixResult;
	    error?: GUIError;
	
	    static createFrom(source: any = {}) {
	        return new GUIFixResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.result = this.convertValues(source["result"], report.FixResult);
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
	export class GUISaveResult {
	    path?: string;
	    cancelled?: boolean;
	    error?: GUIError;
	
	    static createFrom(source: any = {}) {
	        return new GUISaveResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.cancelled = source["cancelled"];
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
	    auto_fix: boolean;
	
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
	        this.auto_fix = source["auto_fix"];
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
	
	export class FixSkip {
	    id: string;
	    line: number;
	    path: string;
	    reason: string;
	    reason_text: string;
	
	    static createFrom(source: any = {}) {
	        return new FixSkip(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.line = source["line"];
	        this.path = source["path"];
	        this.reason = source["reason"];
	        this.reason_text = source["reason_text"];
	    }
	}
	export class FixResult {
	    file: string;
	    output: string;
	    written: boolean;
	    not_written_reason: string;
	    edits: fix.Edit[];
	    skipped: FixSkip[];
	    diff: fix.Hunk[];
	    before: Summary;
	    after: Summary;
	    remaining: FindingView[];
	
	    static createFrom(source: any = {}) {
	        return new FixResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.file = source["file"];
	        this.output = source["output"];
	        this.written = source["written"];
	        this.not_written_reason = source["not_written_reason"];
	        this.edits = this.convertValues(source["edits"], fix.Edit);
	        this.skipped = this.convertValues(source["skipped"], FixSkip);
	        this.diff = this.convertValues(source["diff"], fix.Hunk);
	        this.before = this.convertValues(source["before"], Summary);
	        this.after = this.convertValues(source["after"], Summary);
	        this.remaining = this.convertValues(source["remaining"], FindingView);
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


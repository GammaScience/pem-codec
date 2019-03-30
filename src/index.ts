

export interface PEM_header {
    name : string ;
    value: string;
}
export interface PEM_message {
    type: string;
    data:   Uint8Array;
    headers:    Array<PEM_header> ;
    pre_headers:    Array<PEM_header> ;
}
class PEMh {
    name: string;
    value: string;  // this is often a comma separated list
    toString() {
        return this.name + ': ' + this.value; // FIXME - wrap name/value to N chars wide; breaking on commas
    }
}

class PEM {
    type: string;
    data:   Uint8Array;
    headers:    Array<PEM_header> =new Array(); // may be empty
    pre_headers:    Array<PEM_header> =new Array(); // may be empty
}


var DASHES = "-----";
var OPEN = "BEGIN";
var CLOSE = "END";
var CR = '\\n';
var HDR = '([^ ]+: ){1}(.+,$'+CR+' +)*(.+$){1}';
var DATA = '(.*'+CR+')*';
var BODY = '(((('+HDR+CR+'))*'+CR+')('+DATA+'){1})';
var MAIN =  DASHES+OPEN+' (.+)'+DASHES+CR+
    BODY+
    DASHES+CLOSE+' \\1'+DASHES;



var header_regexp = new RegExp(HDR,'gm');
var main_regexp = new RegExp( MAIN , 'g');


export function decode(msg: string) : PEM_message {
    let decoded_msg: PEM_message = new PEM();
    var vals;
    var parts;
    if ((vals = main_regexp.exec(msg)) != null){
        decoded_msg.type = vals[1];
        while ((parts = header_regexp.exec(vals[2])) != null){
            var hdr: PEM_header = new PEMh();
            hdr.name = parts[1];
            hdr.value= [parts[2],parts[3]].join('') ;
            decoded_msg.headers.push(hdr);
        }
        if (vals[9] !=null){
            var raw = window.atob(vals[9]);
            decoded_msg.data = Uint8Array.from(Array.prototype.map.call(raw,function(x) { 
                return x.charCodeAt(0); 
            }));
       }
    }
    
    return decoded_msg;
}

export function encode(msg: PEM_message) : string {
    let encoded_msg: string;
    var pre: string[] = [];
    var line;
    for (line in msg.pre_headers){
        pre.push( (msg.pre_headers[line]).toString());  // FIXME wrap line.value
    }
    var hdr:string[] = [];
    for (line in msg.headers){
        hdr.push((msg.headers[line]).toString());  // FIXME wrap line.value
    }
    
    var data:string = msg.data.toString();  // FIXME convert from int array to str representation

    encoded_msg = [pre, DASHES + OPEN + ' ' + msg.type + DASHES, hdr, data, DASHES + CLOSE + ' ' + msg.type + DASHES].join('\n');
    
    return encoded_msg;
}

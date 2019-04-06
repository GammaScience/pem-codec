

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

const DASHES = "-----";
const OPEN = "BEGIN";
const CLOSE = "END";
const CR = '\\n';
const HDR = '([^ ]+: ){1}(.+'+CR+' +)*(.+){1}'+CR;
const DATA = '([A-Za-z0-9=+/]*'+CR+')*';
const BODY = '(((('+HDR+'))*)('+DATA+'){1})';
const MAIN =  DASHES+OPEN+' (.+)'+DASHES+CR+
    BODY +
    DASHES+CLOSE+' \\1'+DASHES;



const header_regexp = new RegExp(HDR,'gm');
const main_regexp = new RegExp( MAIN , 'g');


export function decode(msg: string) : PEM_message {

    var decoded_msg:PEM_message = new PEM();
    var vals : RegExpExecArray;
    var parts: RegExpExecArray;
    // reset Regexp
    header_regexp.lastIndex = 0;
    main_regexp.lastIndex = 0;

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

export function encode(msg: PEM_message, max_width:number = 64) : string {


    /**
    * Split a string into chunks of the given size
    * @param  {String} string is the String to split
    * @param  {Number} size is the size you of the cuts
    * @return {Array} an Array with the strings
    */
    function splitString (string, size) {
	    var re = new RegExp('.{1,' + size + '}', 'g');
	    return string.match(re);
    }

    var encoded_msg: string;
    var pre: string[] = [];
    var line;
    for (line in msg.pre_headers){
        pre.push( (msg.pre_headers[line]).toString());  // FIXME wrap line.value
    }
    var hdr:string[] = [];
    for (line in msg.headers){
        hdr.push((msg.headers[line]).toString());  // FIXME wrap line.value ?
    }
    
    var base64String:string = btoa(String.fromCharCode.apply(null, msg.data));
    var base64data:string = splitString(base64String ,max_width).join("\n");
    var msg_parts = [] 
    if(pre.length >0){
        msg_parts.push(pre.join("\n"));
    }
    msg_parts.push( DASHES + OPEN + ' ' + msg.type + DASHES);
    if( hdr.length > 0) {
        msg_parts.push(hdr.join("\n"));
    }
    msg_parts.push(base64data);
    msg_parts.push(DASHES + CLOSE + ' ' + msg.type + DASHES);
    msg_parts.push('');
    encoded_msg = msg_parts.join("\n");
    
    return encoded_msg;
}



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
    constructor( data: string[]) {
        this.name = data[HeaderParts.NAME];
        this.value = '';
        /*
         * These header are based on RFC822 header folding
         * so we are trying to keep folded/indenting whitespace
         * but we need to remove the orginal space after the colon
         * on the first line. Luckily our regexps puts the folded
         * space at the begining of a line at the right hand end
         * of a part. So we can just trim left, then remove the CRLF
         * as per RFC2822.
         */
        if (data[HeaderParts.VALUE]) {
            this.value += data[HeaderParts.VALUE].trimLeft().replace('\n','');
        }
        this.value += data[HeaderParts.LAST_VALUE].trimLeft().replace('\n','');
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
const HDR = '(([^ ]+):){1}(.*'+CR+'[\\t ]+)*(.+){1}'+CR;
const DATA = '([A-Za-z0-9=+/]*'+CR+')*';
const BODY = '(((('+HDR+'))*)('+DATA+'){1})';
const MAIN =  DASHES+OPEN+' (.+)'+DASHES+CR+
    BODY +
//    '('+ DATA +')'+
    DASHES+CLOSE+' \\1'+DASHES;



const header_regexp = new RegExp(HDR,'gm');
const main_regexp = new RegExp( MAIN , 'g');

enum MainParts {
    // Zero is total match
    MSG_TYPE = 1,
    HEADER   = 2,
    BODY     = 10,
}

enum HeaderParts {
    // Zero is total match
    NAME = 2,
    VALUE = 3,
    LAST_VALUE = 4
}

export function decode(msg: string) : PEM_message {

    var decoded_msg:PEM_message = new PEM();
    var doc_parts : RegExpExecArray;
    var hdr_parts: RegExpExecArray;

    /**
     * Function to read headers from a text object and pus them to 
     * destination array.
     * 
     * @param {string} input Test to read headers from. Header
     * @param dest Array to recieve headers.
     */
    function process_headers(input:string, dest: PEM_header[] ) :number {
        // reset Regexp
        header_regexp.lastIndex = 0;
        while ((hdr_parts = header_regexp.exec(input)) != null){
            dest.push( new PEMh( hdr_parts ));
        }
        return header_regexp.lastIndex;
    }

    /*
     * Read any prepending headers nd set the body matcher
     * to start at the index position following these
     * headers
     */
    main_regexp.lastIndex = process_headers(msg, decoded_msg.pre_headers);
    console.log("decoding...");
    if ((doc_parts = main_regexp.exec(msg)) != null){
        decoded_msg.type = doc_parts[MainParts.MSG_TYPE];
        process_headers(doc_parts[MainParts.HEADER],decoded_msg.headers);
        const encoded_body = doc_parts[MainParts.BODY];
        if (encoded_body !=null){
            var raw = window.atob(encoded_body);
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
    function splitString (str: string, size: number) :string[] {
        console.log("split",str);
        const re = new RegExp('.{1,' + size + '}', 'g');
        const rv = str.match(re);
        if ( ! rv ) {
            return [''];
        }
        return rv;
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

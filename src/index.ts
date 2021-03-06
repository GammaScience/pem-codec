


const DASHES = "-----";
const OPEN = "BEGIN";
const CLOSE = "END";
const CR = '\\n';
const HDR = '(([^ ]+):){1}(.*'+CR+'[\\t ]+)*(.+){1}'+CR;
const DATA = '([A-Za-z0-9=+/]*'+CR+')*';
const BODY = '(((('+HDR+'))*)('+DATA+'){1})';
const MAIN =  DASHES+OPEN+' (.+)'+DASHES+CR+
    BODY +
    DASHES+CLOSE+' (.+)'+DASHES;

enum MainParts {
    // Zero is total match
    OPENING_TYPE = 1,
    HEADER       = 2,
    BODY         = 10,
    CLOSING_TYPE = 12,
}

/**
 * Data interface for PEM message block
 * 
 * Optionally initialisation data forma PEM_message 
 */
export interface PEM_Message_Info {
    /**
     * Type of message specified in armour lines
     */
    type: string;
    /**
     * Header which occur immediately after the begin armour
     * line.
     */
    headers?:    Array<PEM_header> ;
    /**
     * Header which occur immediatler before the begin armour
     * line
     */
    pre_headers?:    Array<PEM_header> ;
    /**
     * Binary data of the mesasge as a string.
     */
    string_data?: string;
    /**
     * Binary data of the message as a Uint8Array.
     */
    binary_data?: Uint8Array;
};


/**
 * A class to contain a PEM, or RFC822-like header name/value pair.
 *
 * The name value pair can be trivally constructed from a string
 * representation of a single header. No collapsing of whitespace
 * is attempted.
 * 
 * Once constructed a single line representation is availabe
 * with toString(), or encode() can be use to get a linewrapped
 * encoded version of the string.
 */
export class PEM_header {
    /**
     * The header name.
     */
    name: string;
    /**
     * Unfolded value of the header
     */
    value: string;  // this is often a comma separated list
    toString() {
        return this.name + ': ' + this.value; // FIXME - wrap name/value to N chars wide; breaking on commas
    }
    encode(max_width:number, ) : string {
        // TODO  Extend the API to support breaking on 
        // characters other than space 
        const value = this.toString();
        var rv =  new Array<string>();
        var lastIndex = 0;
        var commitedTo = 0;
        var myexp = / /g;
        var dummy:any;
        while ((dummy= myexp.exec(value)) != null ) { 
            if (myexp.lastIndex > max_width ) {
                rv.push(value.slice(commitedTo,lastIndex));
                commitedTo = lastIndex;
            }
            lastIndex = myexp.lastIndex
        }
        if ((commitedTo != lastIndex) && (value.length - commitedTo > max_width )) {
                rv.push(value.slice(commitedTo,lastIndex));
                commitedTo = lastIndex;
        }
        rv.push(value.slice(commitedTo));

        return  rv.join('\n');
    }
    constructor( header_txt: string ) {
        const sep = header_txt.indexOf(':');

        this.name = header_txt.slice(0,sep);
        /*
         * These header are based on RFC822 header folding
         * so we are trying to keep folded/indenting whitespace
         * but we need to remove the orginal space after the colon
         * on the first line. We alsoe remove any final trailing space.
         */
        this.value = header_txt.slice(sep+1,).trim().replace(/\n/g,'');
    }
}
// From SO 28975896
function isDefined<T>(value: T | undefined | null): value is T {
    return <T>value !== undefined && <T>value !== null;
 }

 /**
 * Represents a PEM Formatted message or object.
 * 
 * A PEM Object has a type, binary data and two different
 * optional locations for headers; either prepending
 * or internal.
 *  
 * PEM format is commonly used for X509 certificates and OpenPGP
 *  messages.
 * 
 */
export class PEM_message implements PEM_Message_Info {

    type: string;
    headers:    Array<PEM_header> ;
    pre_headers:    Array<PEM_header> ;
    string_data: string;


    get binary_data() : Uint8Array {
        return Uint8Array.from(Array.prototype.map.call(this.string_data,function(x) { 
                    return x.charCodeAt(0); 
        }));
    };
    constructor(init: PEM_Message_Info ) { 

        // Check for error conditions in the data supplied
        // (we don't check the existence of 'type' relying on the typechecking)
        if (init.string_data && init.binary_data) {
            throw new Error("Exactly one of binary_data or string_data should be supplied");
        }

        if (!isDefined(init.string_data) && !isDefined(init.binary_data)) {
            throw new Error(`Exactly one of binary_data or string_data should be supplied:${init.string_data}, ${init.binary_data}`);
        }
        var that = this;
        function init_field(fldname:string, ){
            if (init[fldname]) {
                that[fldname] = init[fldname];
            }
        }


        // Default required values.
        this.headers = [];
        this.pre_headers = [];
        this.string_data= "";
        this.type = init.type;
 
        // Load provided values.
        init_field('pre_headers');
        init_field('headers');
        init_field('string_data');
        if (init.binary_data) {
            this.string_data = String.fromCharCode.apply(null, init.binary_data);
        }
 
    }

    /**
     * Decode a PEM formatted object. 
     * 
     * Takes an 'ascii armoured' string representation of the object
     * and return a new instance of PEM_message with the de-armoured 
     * and de-serialised data.
     *
     * @param msg text representation of 'ascii armoured' message
     */
    static decode(msg: string) : PEM_message {

        var doc_parts : RegExpExecArray;
        var hdr_parts: RegExpExecArray;
        var decoded_msg:PEM_message;
        /**
         * Function to read headers from a text object and pus them to 
         * destination array.
         * 
         * @param {string} input Test to read headers from. Header
         * @param dest Array to recieve headers.
         */
        function process_headers(input:string, dest: PEM_header[] ) :number {
            // reset Regexp
            const header_regexp = new RegExp(HDR,'gm');
            while ((hdr_parts = header_regexp.exec(input)) != null){
                dest.push( new PEM_header( hdr_parts[0] ));
            }

            return header_regexp.lastIndex;
        }

        /*
        * Read any prepending headers nd set the body matcher
        * to start at the index position following these
        * headers
        */
        var pre_headers = new Array<PEM_header>();

        const main_regexp = new RegExp( MAIN , 'g');
        main_regexp.lastIndex = process_headers(msg, pre_headers);
        if ((doc_parts = main_regexp.exec(msg)) != null){
            const begin_type = doc_parts[MainParts.OPENING_TYPE];
            const end_type = doc_parts[MainParts.CLOSING_TYPE];

            if (begin_type != end_type) {
                throw new Error( `Mismatched types in guard ${begin_type} <> ${end_type}`);
            }
            decoded_msg = new PEM_message({type: begin_type,
                                           pre_headers:pre_headers,
                                           string_data:""});

            process_headers(doc_parts[MainParts.HEADER],decoded_msg.headers);

            const encoded_body = doc_parts[MainParts.BODY];
            if (encoded_body !=null){
                try {
                    decoded_msg.string_data = window.atob(encoded_body);
                } catch (e) {
                    throw new Error("Invalid data: "+e.message);
                }
            }

        } else {
            // The most likely reason the main regexp to fail is 
            // invlaid headers; but incorrect base64 chars can cause
            // it to 
            throw new Error("Invalid data, invalid headers or malformed object");
        }
        
        return decoded_msg;
    }
   
    encode(max_width:number = 64) : string {
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
       var encoded_msg = "";
       var header: PEM_header;
       for (header of this.pre_headers){
           encoded_msg += (header.encode(max_width) +"\n"); 
       }
       encoded_msg += ( DASHES + OPEN + ' ' + this.type + DASHES + '\n');
       for (header of  this.headers){
           encoded_msg += (header.encode(max_width) +"\n"); 
       }
       if  (this.headers.length > 0) {
           encoded_msg += '\n' //Add blank line
       }
       var base64String = btoa(this.string_data);
       encoded_msg += splitString(base64String ,max_width).join("\n");
       encoded_msg +=( '\n'+ DASHES + CLOSE + ' ' + this.type + DASHES + '\n');
       return encoded_msg;
       
    }
}



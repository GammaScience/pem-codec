// import { describe, it, expect  } from 'jasmine';
import {  PEM_message, PEM_header } from '.';

// Test message encodings follow.

/* 
  ////////////////////////////// USE CASES  //////////////////////////////////////////////
*/

// PEM cert with explanatory txt

const cert_pre_header=`Subject: CN=Atlantis
Issuer: CN=Atlantis
Validity: from 7/9/2012 3:10:38 AM UTC to 7/9/2013 3:10:37 AM UTC
`;

const cert=`-----BEGIN CERTIFICATE-----
MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz
MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs
YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh
Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID
AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB
gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE
LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow
CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0
ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=
-----END CERTIFICATE-----
`;


const pem_message_asym=`-----BEGIN PRIVACY-ENHANCED MESSAGE-----
Proc-Type: 4,MIC-ONLY
Content-Domain: RFC822
Originator-Certificate:
 MIIBlTCCAScCAWUwDQYJKoZIhvcNAQECBQAwUTELMAkGA1UEBhMCVVMxIDAeBgNV
 BAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMQ8wDQYDVQQLEwZCZXRhIDExDzAN
 BgNVBAsTBk5PVEFSWTAeFw05MTA5MDQxODM4MTdaFw05MzA5MDMxODM4MTZaMEUx
 CzAJBgNVBAYTAlVTMSAwHgYDVQQKExdSU0EgRGF0YSBTZWN1cml0eSwgSW5jLjEU
 MBIGA1UEAxMLVGVzdCBVc2VyIDEwWTAKBgRVCAEBAgICAANLADBIAkEAwHZHl7i+
 yJcqDtjJCowzTdBJrdAiLAnSC+CnnjOJELyuQiBgkGrgIh3j8/x0fM+YrsyF1u3F
 LZPVtzlndhYFJQIDAQABMA0GCSqGSIb3DQEBAgUAA1kACKr0PqphJYw1j+YPtcIq
 iWlFPuN5jJ79Khfg7ASFxskYkEMjRNZV/HZDZQEhtVaU7Jxfzs2wfX5byMp2X3U/
 5XUXGx7qusDgHQGs7Jk9W8CW1fuSWUgN4w==
Issuer-Certificate:
 MIIB3DCCAUgCAQowDQYJKoZIhvcNAQECBQAwTzELMAkGA1UEBhMCVVMxIDAeBgNV
 BAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMQ8wDQYDVQQLEwZCZXRhIDExDTAL
 BgNVBAsTBFRMQ0EwHhcNOTEwOTAxMDgwMDAwWhcNOTIwOTAxMDc1OTU5WjBRMQsw
 CQYDVQQGEwJVUzEgMB4GA1UEChMXUlNBIERhdGEgU2VjdXJpdHksIEluYy4xDzAN
 BgNVBAsTBkJldGEgMTEPMA0GA1UECxMGTk9UQVJZMHAwCgYEVQgBAQICArwDYgAw
 XwJYCsnp6lQCxYykNlODwutF/jMJ3kL+3PjYyHOwk+/9rLg6X65B/LD4bJHtO5XW
 cqAz/7R7XhjYCm0PcqbdzoACZtIlETrKrcJiDYoP+DkZ8k1gCk7hQHpbIwIDAQAB
 MA0GCSqGSIb3DQEBAgUAA38AAICPv4f9Gx/tY4+p+4DB7MV+tKZnvBoy8zgoMGOx
 dD2jMZ/3HsyWKWgSF0eH/AJB3qr9zosG47pyMnTf3aSy2nBO7CMxpUWRBcXUpE+x
 EREZd9++32ofGBIXaialnOgVUn0OzSYgugiQ077nJLDUj0hQehCizEs5wUJ35a5h
MIC-Info: RSA-MD5,RSA,
 jV2OfH+nnXHU8bnL8kPAad/mSQlTDZlbVuxvZAOVRZ5q5+Ejl5bQvqNeqOUNQjr6
 EtE7K2QDeVMCyXsdJlA8fA==

LSBBIG1lc3NhZ2UgZm9yIHVzZSBpbiB0ZXN0aW5nLg0KLSBGb2xsb3dpbmcgaXMg
YSBibGFuayBsaW5lOg0KDQpUaGlzIGlzIHRoZSBlbmQuDQo=
-----END PRIVACY-ENHANCED MESSAGE-----
`;


// Message (Symmetric Case)
const pem_message_sym1 = `-----BEGIN PRIVACY-ENHANCED MESSAGE-----
Proc-Type: 4,ENCRYPTED
Content-Domain: RFC822
DEK-Info: DES-CBC,F8143EDE5960C597
Originator-ID-Symmetric: linn@zendia.enet.dec.com,,
Recipient-ID-Symmetric: linn@zendia.enet.dec.com,ptf-kmc,3
Key-Info: DES-ECB,RSA-MD2,9FD3AAD2F2691B9A,
          B70665BB9BF7CBCDA60195DB94F727D3
Recipient-ID-Symmetric: pem-dev@tis.com,ptf-kmc,4
Key-Info: DES-ECB,RSA-MD2,161A3F75DC82EF26,
          E2EF532C65CBCFF79F83A2658132DB47

LLrHB0eJzyhP+/fSStdW8okeEnv47jxe7SJ/iN72ohNcUk2jHEUSoH1nvNSIWL9M
8tEjmF/zxB+bATMtPjCUWbz8Lr9wloXIkjHUlBLpvXR0UrUzYbkNpk0agV2IzUpk
J6UiRRGcDSvzrsoK+oNvqu6z7Xs5Xfz5rDqUcMlK1Z6720dcBWGGsDLpTpSCnpot
dXd/H5LMDWnonNvPCwQUHt==
-----END PRIVACY-ENHANCED MESSAGE-----
`;

const pem_message_sym2=`
-----BEGIN PRIVACY-ENHANCED MESSAGE-----
Proc-Type: 4,ENCRYPTED
Content-Domain: RFC822
DEK-Info: DES-CBC,BFF968AA74691AC1
Originator-Certificate:
 MIIBlTCCAScCAWUwDQYJKoZIhvcNAQECBQAwUTELMAkGA1UEBhMCVVMxIDAeBgNV
 BAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMQ8wDQYDVQQLEwZCZXRhIDExDzAN
 BgNVBAsTBk5PVEFSWTAeFw05MTA5MDQxODM4MTdaFw05MzA5MDMxODM4MTZaMEUx
 CzAJBgNVBAYTAlVTMSAwHgYDVQQKExdSU0EgRGF0YSBTZWN1cml0eSwgSW5jLjEU
 MBIGA1UEAxMLVGVzdCBVc2VyIDEwWTAKBgRVCAEBAgICAANLADBIAkEAwHZHl7i+
 yJcqDtjJCowzTdBJrdAiLAnSC+CnnjOJELyuQiBgkGrgIh3j8/x0fM+YrsyF1u3F
 LZPVtzlndhYFJQIDAQABMA0GCSqGSIb3DQEBAgUAA1kACKr0PqphJYw1j+YPtcIq
 iWlFPuN5jJ79Khfg7ASFxskYkEMjRNZV/HZDZQEhtVaU7Jxfzs2wfX5byMp2X3U/
 5XUXGx7qusDgHQGs7Jk9W8CW1fuSWUgN4w==
Key-Info: RSA,
 I3rRIGXUGWAF8js5wCzRTkdhO34PTHdRZY9Tuvm03M+NM7fx6qc5udixps2Lng0+
 wGrtiUm/ovtKdinz6ZQ/aQ==
Issuer-Certificate:
 MIIB3DCCAUgCAQowDQYJKoZIhvcNAQECBQAwTzELMAkGA1UEBhMCVVMxIDAeBgNV
 BAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMQ8wDQYDVQQLEwZCZXRhIDExDTAL
 BgNVBAsTBFRMQ0EwHhcNOTEwOTAxMDgwMDAwWhcNOTIwOTAxMDc1OTU5WjBRMQsw
 CQYDVQQGEwJVUzEgMB4GA1UEChMXUlNBIERhdGEgU2VjdXJpdHksIEluYy4xDzAN
 BgNVBAsTBkJldGEgMTEPMA0GA1UECxMGTk9UQVJZMHAwCgYEVQgBAQICArwDYgAw
 XwJYCsnp6lQCxYykNlODwutF/jMJ3kL+3PjYyHOwk+/9rLg6X65B/LD4bJHtO5XW
 cqAz/7R7XhjYCm0PcqbdzoACZtIlETrKrcJiDYoP+DkZ8k1gCk7hQHpbIwIDAQAB
 MA0GCSqGSIb3DQEBAgUAA38AAICPv4f9Gx/tY4+p+4DB7MV+tKZnvBoy8zgoMGOx
 dD2jMZ/3HsyWKWgSF0eH/AJB3qr9zosG47pyMnTf3aSy2nBO7CMxpUWRBcXUpE+x
 EREZd9++32ofGBIXaialnOgVUn0OzSYgugiQ077nJLDUj0hQehCizEs5wUJ35a5h
MIC-Info: RSA-MD5,RSA,
 UdFJR8u/TIGhfH65ieewe2lOW4tooa3vZCvVNGBZirf/7nrgzWDABz8w9NsXSexv
 AjRFbHoNPzBuxwmOAFeA0HJszL4yBvhG
Recipient-ID-Asymmetric:
 MFExCzAJBgNVBAYTAlVTMSAwHgYDVQQKExdSU0EgRGF0YSBTZWN1cml0eSwgSW5j
 LjEPMA0GA1UECxMGQmV0YSAxMQ8wDQYDVQQLEwZOT1RBUlk=,
 66
Key-Info: RSA,
 O6BS1ww9CTyHPtS3bMLD+L0hejdvX6Qv1HK2ds2sQPEaXhX8EhvVphHYTjwekdWv
 7x0Z3Jx2vTAhOYHMcqqCjA==

qeWlj/YJ2Uf5ng9yznPbtD0mYloSwIuV9FRYx+gzY+8iXd/NQrXHfi6/MhPfPF3d
jIqCJAxvld2xgqQimUzoS1a4r7kQQ5c/Iua4LqKeq3ciFzEv/MbZhA==
-----END PRIVACY-ENHANCED MESSAGE-----
`;

describe('the decode function ', () => {
    // Test some simple error conditions
    it ('should throw an error including the string "Mismatched types" if the type name and begin and end string of the armour do not match', () =>{
        expect( () =>{
            PEM_message.decode(`-----BEGIN FOO-----
qwertyui
-----END BAR-----
            `);
        }).toThrowMatching(
          (x) => { return  x.message.search('Mismatched types') != -1 }
        );

     });
    it ('should throw an error including the string "invalid headers" if the headers are invalid',() =>{ 
        // Just check one way the headers can be invalid for now.
        expect( () =>{
            const invalid = PEM_message.decode(`-----BEGIN FOO-----
BlahBlah data

qwertyui
-----END FOO-----
            `);
            console.log("inv-h",invalid);
        }).toThrowMatching(
          (x) => { return  x.message.search('invalid headers') != -1 }
        );


    } );
    it ('should throw an error including the string "Invalid data" if the data block isn\'t valid base64' ,() => {
         expect( () =>{
            const invalid = PEM_message.decode(`-----BEGIN FOO-----
qwertyu@
-----END FOO-----
            `);
            console.log("inv-d",invalid);
        }).toThrowMatching(
          (x) => { return  x.message.search('Invalid data') != -1 }
        );


       
    });
    
    
    // Tests with valid inputs 
    it ('should extract the message type from the PEM message',() => {
        for ( const encoded_data of [ 
                                    { in:cert, t:"CERTIFICATE" },
                                    { in:pem_message_sym1, t:"PRIVACY-ENHANCED MESSAGE" },
                                    { in:pem_message_asym, t:"PRIVACY-ENHANCED MESSAGE" },
                                    { in:cert_pre_header+cert, t:"CERTIFICATE" },
                                    ]){
            const data:PEM_message = PEM_message.decode(encoded_data.in);
            expect(data.type).toBe(encoded_data.t);
        }
    });
    it ('should return an object conforming to the PEM_message interface wi the base64 string decoded as the data attributewith a valid pem messge' ,() =>  {
        const data = '\x00\x01\x02ABCD';
        const encoded_data = btoa(data);
        const encoded_msg = `-----BEGIN FOO-----
${encoded_data}
-----END FOO-----
        `;
        const decoded = PEM_message.decode(encoded_msg);
        expect(decoded.headers).toBeDefined();
        expect(decoded.pre_headers).toBeDefined();
        expect(decoded.type).toBe('FOO');
        expect(decoded.binary_data).toEqual(new Uint8Array([0,1,2,65,66,67,68]));
        expect(decoded.string_data).toEqual(data);
    });
    it ('should return an object conforming to the PEM_message interface with any enclosed headers listed as the header atribute', () =>{
        const encoded_data = pem_message_sym1;
        const data =PEM_message.decode(encoded_data);
        expect(data.headers.length).toBe(8);
        expect(data.headers[0].name).toBe('Proc-Type');
        expect(data.headers[1].name).toBe('Content-Domain');
        expect(data.headers[2].name).toBe('DEK-Info');
        expect(data.headers[3].name).toBe('Originator-ID-Symmetric');
        expect(data.headers[4].name).toBe('Recipient-ID-Symmetric');
        expect(data.headers[5].name).toBe('Key-Info');
        expect(data.headers[6].name).toBe('Recipient-ID-Symmetric');
        expect(data.headers[7].name).toBe('Key-Info');
        expect(data.headers[0].value).toBe('4,ENCRYPTED');
        expect(data.headers[1].value).toBe('RFC822');
        expect(data.headers[2].value).toBe('DES-CBC,F8143EDE5960C597');
        expect(data.headers[3].value).toBe('linn@zendia.enet.dec.com,,');
        expect(data.headers[4].value).toBe('linn@zendia.enet.dec.com,ptf-kmc,3');
        expect(data.headers[5].value).toBe('DES-ECB,RSA-MD2,9FD3AAD2F2691B9A,          B70665BB9BF7CBCDA60195DB94F727D3');
        expect(data.headers[6].value).toBe('pem-dev@tis.com,ptf-kmc,4');
        expect(data.headers[7].value).toBe('DES-ECB,RSA-MD2,161A3F75DC82EF26,          E2EF532C65CBCFF79F83A2658132DB47');
    });
    it ('should return an object conforming to the PEM_message interface with any pre-pended headers listed as the pre-header atribute', () =>{
        const encoded_data = cert_pre_header+cert;
        const data =PEM_message.decode(encoded_data);
        expect(data.pre_headers.length).toBe(3);
        expect(data.pre_headers[0].name).toBe('Subject');
        expect(data.pre_headers[1].name).toBe('Issuer');
        expect(data.pre_headers[2].name).toBe('Validity');
        expect(data.pre_headers[0].value).toBe('CN=Atlantis');
        expect(data.pre_headers[1].value).toBe('CN=Atlantis');
        expect(data.pre_headers[2].value).toBe('from 7/9/2012 3:10:38 AM UTC to 7/9/2013 3:10:37 AM UTC');
 
    });
});

describe('the encode function ', () => {
    it('should encode even if the headers are undefined, and data is empty', () => {
       const enc = new PEM_message({
                    pre_headers: undefined, 
                    headers: undefined,
                    type: "SILLY TEST",
            //        binary_data: new Uint8Array(),
                    string_data: ''
                }).encode();
        expect(enc).toBeTruthy();
    })
});

describe('the PEM Message class ', () => {
    it('should fail to construct with no data',() => {
        expect(()=>{
            new PEM_message({type:'foo'});
        }).toThrow();
    });
    it('should fail to construct if both data fields are defined', () =>{
        expect(()=>{
            new PEM_message({type:'foo', 
                             string_data:'aaa', 
                             binary_data: new Uint8Array([0,1,2])})
        }).toThrow();
    });
    it('should set the headers values from the provided header value' ,() =>{
         const tst_hdr = new PEM_header('bar: baz')
         const msg = new PEM_message({type:'foo', 
                             string_data:'aaa', 
                             headers: [ tst_hdr ]
                            })
         expect(msg.headers.length).toBe(1);
         expect(msg.headers[0]).toBe(tst_hdr);
    });
    it('should set the pre_headers values from the provided pre_header value',() =>{
         const tst_hdr = new PEM_header('bar: baz')
         const msg = new PEM_message({type:'foo', 
                             string_data:'aaa', 
                             pre_headers: [ tst_hdr ]
                            })
         expect(msg.pre_headers.length).toBe(1);
         expect(msg.pre_headers[0]).toBe(tst_hdr);
 
    });
    it('should set the pre_headers values to the array if pred_headers are not supplied', ()=>{
         const msg = new PEM_message({type:'foo', 
                             string_data:'aaa', 
                            })
         expect(msg.pre_headers.length).toBe(0);
    });
    it('should set the headers values to the array if headers are not supplied', () => {
          const msg = new PEM_message({type:'foo', 
                             string_data:'aaa', 
                            })
         expect(msg.headers.length).toBe(0);
        
    });
    it('should set the data from the provieded string_data value', () =>{
        const msg = new PEM_message({type:'foo', 
                             string_data:'aaa', 
                            })
         expect(msg.string_data).toBe('aaa');
         expect(msg.binary_data).toEqual(new Uint8Array([97,97,97]));
              
    });
    it('should set the data from the provieded binary_data value', () =>{
         const msg = new PEM_message({type:'foo', 
                             binary_data: new Uint8Array([1,2,3]), 
                            })
         expect(msg.string_data).toBe('\x01\x02\x03');
         expect(msg.binary_data).toEqual(new Uint8Array([1,2,3]));
        
    });

});
describe('the whole module ', () => {

    function dec_enc_rt(m: string): string {
        return PEM_message.decode(m).encode();
    }
    function enc_dec_rt(m: PEM_message): PEM_message {
        return PEM_message.decode(m.encode());
    }


    it (' should be able to roundtrip data', () => {
        const encoded_data = cert;
        expect(dec_enc_rt(encoded_data)).toBe(encoded_data);
    })

});



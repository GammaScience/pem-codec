# PEM Codec

[![Unittests](https://github.com/GammaScience/pem-codec/actions/workflows/unittest.yml/badge.svg)](https://github.com/GammaScience/pem-codec/actions/workflows/unittest.yml)

A pure JS module intended primarily for use in the browser, 
to encode and decode PEM style ascii armoured data.

The could be a PEM message, a openGPG message or a
X509 certificate or key. All of these types of
objects use the same basic data format and can share this 
module.


PEM Codec has no dependencies on the browser environment apart
from the atob/btoa Base64 funtions.

A PEM_Message object can be initialised as simply as
`
o = new PEM_Message({
    type: "TEST OBJECT",
    string_data: "abcde"
});
`

The encoded string of the object can be extracted with encode like:
`
var encoded = o.encode();
`

And it can be roundtripped back to an object as simply as:
`
var o2 = PEM_Message.decode(encoded);
`


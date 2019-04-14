# PEM Codec

A pure JS module intended primarily for use in the browser, 
to encode and decode PEM style ascii armoured data.

The could be a PEM message, a openGPG message or a
X509 certificate or key. All of these types of
objects use the same basice data format and can shar this 
module.


PEM Codec has no dependencies on the browser environmant apart
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


import Java from "frida-java-bridge";
setTimeout(function() {
    Java.perform(function () {
        var keyStoreLoadStream = Java.use('java.security.KeyStore')['load'].overload('java.io.InputStream', '[C');

        /* following function hooks to a Keystore.load(InputStream stream, char[] password) */
        keyStoreLoadStream.implementation = function(stream:any, charArray:string) {

            /* sometimes this happen, I have no idea why, tho... */
            if (stream == null) {
                /* just to avoid interfering with app's flow */
                this.load(stream, charArray);
                return;
            }

            /* just to notice the client we've hooked a KeyStore.load */
            send({event: '+found'});

            /* read the buffer stream to a variable */
            var hexString = readStreamToHex (stream);

            /* send KeyStore type to client shell */
            send({event: '+type', certType: this.getType()});

            /* send KeyStore password to client shell */
            send({event: '+pass', password: charArray});

            /* send the string representation to client shell */
            send({event: '+write', cert: hexString});

            /* call the original implementation of 'load' */
            this.load(stream, charArray);

            /* no need to return anything */
        }
    });
},0);

/* following function reads an InputStream and returns an ASCII char representation of it */
function readStreamToHex (stream:any) {
    var data = [];
    var byteRead = stream.read();
    while (byteRead != -1)
    {
        data.push( ('0' + (byteRead & 0xFF).toString(16)).slice(-2) );
                /* <---------------- binary to hex ---------------> */
        byteRead = stream.read();
    }
    stream.close();
    return data.join('');
}

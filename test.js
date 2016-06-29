var lookup = require('dnsbl-lookup');

    var dnsbl = new lookup.dnsbl('174.94.149.64');
    var result = {};
    dnsbl.on('error',function(err,bl){
        console.log("******"+ err + "******"+ bl);
    });
    dnsbl.on('data',function(response,bl){
        console.log(bl.zone);
        result[bl] = response;
    });
    dnsbl.on('done', function(){
        console.log(result);
    });

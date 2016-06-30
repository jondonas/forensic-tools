var lookup = require('dnsbl-lookup');

    var dnsbl = new lookup.dnsbl('174.94.149.64');
    console.log(new Date());
    dnsbl.on('error',function(err,bl){
    result = [];
    });
    dnsbl.on('data',function(response,bl){
        if (response.status == "listed") {
            console.log(bl.zone);
            result.push(bl.zone);
        }
    });
    dnsbl.on('done', function(){
        console.log("Done");
        console.log(new Date());
    });

    setTimeout(function() { done() }, 1000 );

    function done () {
        console.log(result); 
        console.log("done");
    }

var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var execSync = require('exec-sync');
var session = require('express-session');
var http = require('http');
var _ = require("underscore");
var exec = require('child_process').exec;
var MongoClient = require('mongodb').MongoClient;
var favicon = require('serve-favicon');
var path = require('path'), fs=require('fs');
//var dns = require('dns');

app.use(bodyParser.json()); // support json encoded bodies
app.use(bodyParser.urlencoded({ extended: true })); // support encoded bodies
app.set('view engine', 'jade'); // use jade as a template engine
app.use(express.static(__dirname)); // set the static folder location
app.use(favicon('/home/jdonas/web-interface/template/static/img/favicon.png')); // serves favicon

// session to keep track of errors to be displayed
app.use(session({ secret: 'rand0m5tr1ng', resave: false, saveUninitialized: false}));


////////////////////////////////////////////


app.get('/', function (req, res) {
    res.render("/home/jdonas/web-interface/template/views/ip-home");
});


////////////////////////////////////////////


app.get('/cases', function (req, res) {
        res.render("/home/jdonas/web-interface/template/views/cases");
});


////////////////////////////////////////////

// gets a list of all disk images in /mnt directory for file viewer
app.post('/test', function (req, res) {
    var dir = req.body.dir;
    var ext = ['.001', '.dd'];

    var html = '<ul class="jqueryFileTree" style="display: none;">';
    try {
        html = '<ul class="jqueryFileTree" style="display: none;">';
        var files = fs.readdirSync(dir);
        files.forEach(function(file){
            var path = dir + file;
            var stats = fs.statSync(path)
            if (stats.isDirectory()) {
                html += '<li class="directory collapsed"><a href="#" rel="' + path  + '/">' + file + '</a></li>'; 
            } 
            else {
                for (var x = 0; x < ext.length; ++x) {
                    if (file.indexOf(ext[x]) >= 0) {
                        var extension = file.split('.')[1];
                        html += '<li class="file ext_' + extension + '"><a href="#" rel='+ path + '>' + file + '</a></li>';
                    }
                }
            }
        });
        html += '</ul>';
    } 
    catch(e) {
        html += '<i>Could not load directory</i>';
        html += '</ul>';
    }

    res.send(html)
});


////////////////////////////////////////////


app.get('/forensic-cases', function (req, res) {
    var url = "mongodb://jdonas:NCIR4525@192.168.0.113/paladion-cases";
    MongoClient.connect(url, function(err, db) {
        if (err) {
            res.send("Oops! We seem to have run into an error: " + err);
        }
        else {
            
            var collection = db.collection('cases');
            collection.find({}).toArray(function(err, docs) {
                res.render("/home/jdonas/web-interface/components/scan-interface/views/index", { cases : docs,});
            db.close();
            });
        }
    });
});


////////////////////////////////////////////

// view to start a scan for a disk image
app.post('/start-scan', function(req, res) {
    var name = req.body.case1.replace(/\s/g,'');
    var diskimage = req.body.diskimage;
    
    var url = "mongodb://jdonas:NCIR4525@192.168.0.113/paladion-cases?authSource=admin";
    MongoClient.connect(url, function(err, db) {
        var collection = db.collection('cases');
        
        // does a check to see if casename already exists
        collection.count({ "case": name}, function (err, num) {
            if (num >= 1)
                res.send("Exists");
            else {
                collection.insertOne( {
                    "case": name,
                    "diskimage": diskimage
                }, function (err, result) {
                    if (err) {
                        res.send(err);
                        console.log(err);
                    }
                    else {
                        db.close();
                        res.send("Success");
                    }
                });
            }
        });
    });
});


////////////////////////////////////////////


// retrieves and displays case info from mongodb
app.get('/cases/:case', function (req, res) {
    var search = 
      [{"virustotalpercentage": null}, {"virustotalpercentage": 0}, 
       {"virustotalpercentage": {"$gt": 5}}, {"virustotalpercentage": {"$gt": 10}}, 
       {"nsrl": null}, {"nsrl": true}, {"nsrl": false}, {"clamavmalware": null}, 
       {"clamavmalware": true}, {"clamavmalware": false}, {"wildfiremalware": null},
       {"wildfiremalware": true}, {"wildfiremalware": false}, {}, 
       {"virustotaldate": null, "nsrl": false, "filetype": /exe|dll/i},
       {"virustotalpercentage": {$ne: null}}, {"virustotaldate": null, "nsrl": true},
       {"virustotaldate": null, "nsrl": false, "filetype": {$not: /exe|dll/i}}];
    var stages =
      [{"stagename": "fingerprinting"}, {"stagename": "nsrl"},
       {"stagename": "chromehistory"}, {"stagename": "virustotal"},
       {"stagename": "wildfire"}, {"stagename": "clamav"}]
    var results = [];
    var stage_results = [];

    var finished = _.after(1, doRender);
    var clam_detections;
    var vtotal_detections;

    // connects to mongo
    var case_name = req.params.case;
    var url = "mongodb://jdonas:NCIR4525@192.168.0.113/" + case_name +"?authSource=admin";
    MongoClient.connect(url, function(err, db) {
        var finInfo = _.after(search.length+stages.length+2, doClose);
        var collection = db.collection('files');

        // gets count info
        search.forEach(function (value, i) {
            collection.count(value, function (err, num) {
                results.push({index: i, result: num});
                finInfo();
            });
        });

        // gets entry info for clamav
        collection.find({"clamavmalware": true, nsrl:false}).toArray(function(err, docs) {
            clam_detections = docs;
            for (var i = 0; i < clam_detections.length; ++i) {
                var splitpath = clam_detections[i]["fullpath"].split('/');
                clam_detections[i].filename = splitpath[splitpath.length-1];
            }
            finInfo();
        });

        // gets entry info for vtotal
        collection.find({"virustotalpercentage":{"$gt": 5}}).toArray(function(err, docs) {
            vtotal_detections = docs;
            for (var i = 0; i < vtotal_detections.length; ++i) {
                var splitpath = vtotal_detections[i]["fullpath"].split('/');
                vtotal_detections[i].filename = splitpath[splitpath.length-1];
            }
            finInfo();
        });

        // gets completed stages
        var collection2 = db.collection('stages');
        stages.forEach(function (value, i) {
            collection2.count(value, function (err, num) {
                stage_results[value["stagename"]] = num;
                finInfo();
            });
        });

/*        var dates = []
        var date = new Date();
        var day = date.getDate();
        var month = date.getMonth();
        var start_day = day;

        // gets chrome history data
        var collection3 = db.collection('urlhistory');
        collection3.find({download:{$exists: false}}).toArray(function(err, docs) {
            for (var i = 0; i < docs.length; ++i) {
                history.push({group: 1, content: '&zwnj;', start: docs[i]["visittime"]});
            }
            finInfo();
        });

        collection3.find({download:{$exists: true}}).toArray(function(err, docs) {
            for (var i = 0; i < docs.length; ++i) {
                history.push({group: 2, content: '&zwnj;', start: docs[i]["visittime"]});
            }
            finInfo();
        }); */

        // function to call when all mongo calls are complete
        function doClose() {
            db.close();
            finished();
        }
    });

    // calculates statistics and renders page
    function doRender() {

        var acm_times = [];
        
        // parses date format for timeline vis
        function getTime(time) {
            time = time.toString().split(' ');
            var month = new Date(Date.parse(time[1] +" 1, 2000")).getMonth()+1
            var hms = time[4].split(':');
            var new_time = time[3] + '-' +  ("00" + month).slice(-2) + '-' + time[2] + 'T' + hms[0] + ':' + hms[1] + ':' + hms[2] + '.000Z';
            return new_time;
        }

        // retrieves relevant times for timeline vis
        function acmTimes(in_arr, res_arr) {
            for (var i = 0; i < in_arr.length; ++i) {
                var start1, start2, start3;
                
                if (in_arr[i]["atime"])
                    start1 = getTime(in_arr[i]["atime"]);
                else
                    start1 = "error";
                res_arr.push({group: 1, content: in_arr[i]["filename"], start: start1 });

                if (in_arr[i]["ctime"])
                    start2 = getTime(in_arr[i]["ctime"]);
                else
                    start2 = "error";
                res_arr.push({group: 2, content: in_arr[i]["filename"], start: start2 });

                if (in_arr[i]["mtime"])
                    start3 = getTime(in_arr[i]["mtime"]);
                else
                    start4 = "error";
                res_arr.push({group: 3, content: in_arr[i]["filename"], start: start3 });
            }
        }
        
        if (!(clam_detections.length + vtotal_detections.length > 50)) {
            acmTimes(clam_detections, acm_times);
            acmTimes(vtotal_detections, acm_times);
        }

        // used to sort the results list
        function compare(a, b) {
          if (a.index < b.index)
            return -1;
          else (a.index > b.index)
            return 1;
        }

        // prepares statistics
        results.sort(compare);
        var left = results[4].result + results[14].result + results[6].result - results[13].result + results[7].result;
        var tot = results[13].result + results[14].result + results[15].result + results[6].result;
        var percent = Math.floor(((tot - left)/tot)*100);

        if (percent > 100)
            percent = 100;

        var status;
        var progress;
        if (results[5].result == 0 && results[6].result == 0) {
            progress = "progress-bar-striped progress-bar-warning active";
            status = "HASHING IN PROGRESS";
            percent = 100;
        }
        else if (percent == 100) {
            progress = "progress-bar-success";
            status = "COMPLETE";
        }
        else {
            var stage;
            if (stage_results["wildfire"])
                stage = "% (STAGE: ClamAV)";
            else if (stage_results["virustotal"])
                stage = "% (STAGE: WildFire)";
            // removed for now for compatibility
            //else if (stage_results["chromehistory"])
                //stage = "% (STAGE: VirusTotal)";
            else if (stage_results["nsrl"])
                stage = "% (STAGE: VirusTotal)";
                //stage = "% (STAGE: Chrome History)";
            else if (stage_results["fingerprinting"])
                stage = "% (STAGE: NSRL)";
            else
                stage = "% COMPLETE";

            progress = "progress-bar-striped active";
            status = percent.toString() + stage;
        }

        res.render("/home/jdonas/web-interface/components/scan-interface/views/results", 
          { percent: percent, progress: progress, tot_files: results[13].result, case_name: case_name, status: status, clam_detections: clam_detections, vtotal_detections: vtotal_detections, acm_times: acm_times,
            vtotal_null: results[0].result, vtotal_0: results[1].result, vtotal_gt5: results[2].result, vtotal_gt10: results[3].result,
            nsrl_null: results[4].result, nsrl_true: results[5].result, nsrl_false: results[6].result,
            clamav_null: results[7].result, clamav_true: results[8].result, clamav_false: results[9].result,
            wfire_null: results[10].result, wfire_true: results[11].result, wfire_false: results[12].result,
            vtotal_pending: results[14].result, vtotal_ne_null: results[15].result,
            vtotal_known: results[16].result, vtotal_neutral: results[17].result});
    }

});


////////////////////////////////////////////

// home page for ip-checker module
app.get('/ip-check', function (req, res) {
  var data = JSON.parse(execSync('/home/jdonas/web-interface/components/ip-checker/scripts/num_ip.py'));
  var count = data["aggregations"]["counts"]["value"];
  // keeps track of entered data when error page is displayed
  if (req.session.error) {
    res.render("/home/jdonas/web-interface/components/ip-checker/views/index", { error: req.session.message, ip: req.session.ip, ip_count: count });
    req.session.destroy();
  }
  else
    res.render("/home/jdonas/web-interface/components/ip-checker/views/index", { error: "", ip: "", ip_count: count });
});


////////////////////////////////////////////


// processes input
app.post('/process', function(req, res) {
  var ip = req.body.ip.replace(/\s/g,'');
  var cache = req.body.query;

  // regex to check ip format
  var ipformat = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  //checks if documents exist
  function ipCheck(ip) {
    var check = JSON.parse(execSync('/home/jdonas/web-interface/components/ip-checker/scripts/ip-check.py ' + ip));
    if (check["exists"])
      return true;
    return false;
  }

  // checks if input is a valid ip
  if (!ip.match(ipformat)) {
    req.session.error = true;
    req.session.ip = ip;
    req.session.message = "Please enter a valid IP address";
    res.redirect('/ip-check');
  }
  //checks if ip has been cached already
  else if (cache == 0 && !ipCheck(ip)) {
    req.session.error = true;
    req.session.ip = ip;
    req.session.message = "IP has not been cached. Please select 'New Query'";
    res.redirect('/ip-check');
  }
  // does the processing
  else {

    var finished = _.after(3, doRender);

/*    // resolve ip to hostname
    var iptohost;
    var hosttoip;
    dns.lookupService(ip, 80, function(err, hostname, service) {
      iptohost = hostname;
console.log(iptohost);
      // resolve hostname to ip
      dns.lookup(iptohost, function(err2, address, family) {
        hosttoip = address;
  console.log(hosttoip);
        finished();
      });
    });*/

    // gets ip location
    var url = "http://ipinfo.io/"+ip+"/loc";
    var loc = '';
    http.get(url, function(http_res) {
      http_res.setEncoding('utf8');
      http_res.on("data", function(data) {
        loc += data;
      });
      http_res.on("end", function() {
        finished();
      });
    });

    // runs shell commands
    if (cache == 1) {
      var placeholder = execSync('/home/jdonas/web-interface/components/ip-checker/scripts/gather.sh ' + ip);
    }

    // gets VirusTotal json from elasticsearch
    var vir_stdout;
    exec('/home/jdonas/web-interface/components/ip-checker/scripts/vir-query.py ' + ip, function(error, stdout, stderr) {
      vir_stdout = JSON.parse(stdout);
      finished();
    });

    // gets registrar json from elasticsearch
    var reg_stdout;
    var query_time = 0;
    exec('/home/jdonas/web-interface/components/ip-checker/scripts/reg-query.py ' + ip + ' 0', function(error, stdout, stderr) {
      reg_stdout = JSON.parse(stdout);
      if (reg_stdout["hits"]["total"] > 1) {
        var datetime = reg_stdout["hits"]["hits"][0]["_source"]["datetime"];

        // this allows multiple, most-recent regristar entries to be displayed
        reg_stdout = '';
        exec('/home/jdonas/web-interface/components/ip-checker/scripts/reg-query.py ' + ip + ' 1 "' + datetime + '"', function(error, stdout, stderr) {
          reg_stdout = JSON.parse(stdout);
          query_time = reg_stdout["took"];
          finished();
        });

      }
      else
        finished();
    });

    // VirusTotal statistics helper: gets detection count
    function detCount(arr) {
      var size = arr.length;
      return size.toString();
    }

    // VirusTotal statistics helper: gets detection score
    function detAvg(arr) {
      var size = arr.length;
      var pos = 0;
      var total = 0;
      for (var i = 0; i < size; ++i) {
        pos += arr[i]["positives"];
        total += arr[i]["total"];
      }
      return Math.round((pos/total)*100).toString() + "%";
    }

    // VirusTotal statistics helper: gets score color rating
    function getColor(percent) {
      var per = parseInt(percent);
      if (per >= 50)
        return "red";
      else if (per >= 10)
        return "orange";
      else
        return "limeGreen";
    }

    // registrar statistics helper
    function catNames(arr, ind) {
      var len = arr.length;
      var str = '';
      for (var i = 0; i < len; ++i) {
        if (i == 0)
          str += arr[i]["_source"][ind];
        else if (i == 2) {
          str += ", (more)...";
          break; }
        else
          str += ", " + arr[i]["_source"][ind];
      }
    return str;
    }

    function doRender() {

      query_time += vir_stdout["took"] + reg_stdout["took"];
      // VirusTotal statistics
      var d_comm, d_down, d_urls, resolutions, comm_score, down_score, urls_score;
      d_comm = d_down = d_urls = resolutions = "None";
      comm_score = down_score = urls_score = "N/A";

      var vir_html;
      var colors = ["limeGreen", "black", "limeGreen", "black", "limeGreen", "black", "limeGreen"];

      if (vir_stdout["hits"]["total"] == 0 ||
          !("response_code" in vir_stdout["hits"]["hits"][0]["_source"]) ||
          vir_stdout["hits"]["hits"][0]["_source"]["response_code"] != 1)
        vir_html = '<p style="color:orange; text-align: center;"><i>No VirusTotal info available for ' + ip + '</i></p>';
      else {
        var vir_res = vir_stdout["hits"]["hits"][0]["_source"];
        if ("detected_communicating_samples" in vir_res) {
        d_comm = detCount(vir_res["detected_communicating_samples"]);
          comm_score = detAvg(vir_res["detected_communicating_samples"]);
        colors[0] = getColor(d_comm);
        colors[1] = getColor(comm_score.slice(0, -1));
          if (d_comm == "100")
            d_comm = "100+";
        }
        if ("detected_downloaded_samples" in vir_res) {
          d_down = detCount(vir_res["detected_downloaded_samples"]);
          down_score = detAvg(vir_res["detected_downloaded_samples"]);
          colors[2] = getColor(d_down);
          colors[3] = getColor(down_score.slice(0, -1));
          if (d_down == "100")
            d_down = "100+";
        }
        if ("detected_urls" in vir_res) {
          d_urls = detCount(vir_res["detected_urls"]);
          urls_score = detAvg(vir_res["detected_urls"]);
          colors[4] = getColor(d_urls);
          colors[5] = getColor(urls_score.slice(0, -1));
          if (d_urls == "100")
            d_urls = "100+";
        }
        if ("resolutions" in vir_res) {
          resolutions = detCount(vir_res["resolutions"]);
          colors[6] = getColor(resolutions.slice(0, -1));
          if (resolutions == "1000")
            resolutions = "1000+";
        }

        vir_html = "<img src='components/ip-checker/static/comm.png' height='30'/>" +
               "<p style='text-indent: 30px; margin-bottom: 10px;'><b>Detected Communicating Samples:</b> " + "<span style='color: " + colors[0] + "'>" + d_comm + "</span>" + "</p>" +
             "<p style='text-indent: 100px; font-size: 80%; margin-top: 0px;'><b>AV Detection Rate:</b> " + "<span style='color: " + colors[1] + "'>" + comm_score + "</span>" + "</p>" +
               "<img src='components/ip-checker/static/down.png' height='30'/>" +
               "<p style='text-indent: 30px; margin-bottom: 10px;'><b>Detected Downloaded Samples:</b> " + "<span style='color: " + colors[2] + "'>" + d_down + "</span>" + "</p>" +
               "<p style='text-indent: 100px; font-size: 80%; margin-top: 0px;'><b>AV Detection Rate:</b> " + "<span style='color: " + colors[3] + "'>" + down_score + "</span>" + "</p>" +
               "<img src='components/ip-checker/static/urls.png' height='30'/>" +
               "<p style='text-indent: 30px; margin-bottom: 10px;'><b>Detected URLs:</b> " + "<span style='color: " + colors[4] + "'>" + d_urls + "</span>" + "</p>" +
               "<p style='text-indent: 100px; font-size: 80%; margin-top: 0px;'><b>AV Detection Rate:</b> " + "<span style='color: " + colors[5] + "'>" + urls_score + "</span>" + "</p>" +
               "<img src='components/ip-checker/static/res.png'  height='30'/>" +
             "<p style='text-indent: 30px;'><b>DNS Resolutions:</b> " + "<span style='color: " + colors[6] + "'>" + resolutions + "</span>" + "</p>";
      }

      // registrar statistics
      var reg_html;
      var reg_res = reg_stdout["hits"]["hits"];

      if (reg_stdout["hits"]["total"] == 0) {
        reg_html = '<p style="color:orange; text-align: center;"><i>No registrar info available for ' + ip + '</i></p>';

  }    else {
        var title1 = "Netname:";
        var title2 = "Organization:";
        if (reg_res.length > 1) {
          title1 = "Netnames:"
          title2 = "Organizations:"
        }
        var name1 = catNames(reg_res, "netname");
        var name2 = catNames(reg_res, "organization");

        reg_html = "<div style='display: inline-block; text-align: left; padding: 10px 0px;'><b>" + title1 + "</b> <span style='font-size: 80%;'>" + name1 + "</span><br>" +
                 "<b>" + title2 + "</b> <span style='font-size: 80%;'>" + name2 + "</span></div>";
      }

      res.render("/home/jdonas/web-interface/components/ip-checker/views/results",
        { vir_json: vir_stdout, reg_json: reg_stdout, ip: ip, loc: loc,
          time: query_time, vir_insert: vir_html, reg_insert: reg_html });

    }

  }
});


////////////////////////////////////////////


app.get('/process', function (req, res) {
  res.redirect('/');
});


////////////////////////////////////////////


// handling 404 errors
app.get('*', function(req, res, next) {
  var err = new Error();
  err.status = 404;
  next(err);
});

app.use(function(err, req, res, next) {
  if(err.status !== 404) {
    return next();
  }
  res.redirect('/');
});


////////////////////////////////////////////


// runs site
app.listen(80);

// Data input format: ({ obj, text, size }) or ( doc )
function main(doc) {
    // https://docs.umbrella.com/deployment-umbrella/docs/log-formats-and-versioning
    // https://docs.umbrella.com/deployment-umbrella/docs/proxy-log-formats

    let csvKeyMap = {
        "0":"timestamp",
        "1":"policyIdentity",
        "2":"internalIp",
        "3":"externalIp",
        "4":"destinationIP",
        "5":"contentType",
        "6":"verdict", // "action" ? (2024-03-21)
        "7":"url",
        "8":"referer",
        "9":"userAgent",
        "10":"statusCode",
        "11":"requestSize",
        "12":"responseSize",
        "13":"responseBodySize",
        "14":"sha256",
        "15":"categories",
        "16":"AVDetections",
        "17":"PUAs",
        "18":"AMPDisposition",
        "19":"AMPMalwareName",
        "20":"AMPScore",
        "21":"policyIdentityType",
        "22":"blockedCategories",
        "23":"identities",
        "24":"identityTypes",
        "25":"requestMethod",
        "26":"DLPStatus",
        "27":"certificateErrors",
        "28":"filename",
        "29":"rulesetID",
        "30":"ruleID",
        "31":"destinationListIDs",
        "32":"isolateAction",
        "33":"fileAction",
        "34":"warnStatus",
        "35":"forwardingMethod",
        "36":"producer"
    }
    
    let obj = {}

    let text = doc.text
    let arr = decoder_CSV(text)
    //printf("%v",arr)
    let fields = {}
    for i, v = range arr {
        let k = csvKeyMap[sprintf("%d",i)]
        if (!k) {
            //printf(sprintf("%d",i))
            continue
        } 
        if (v == "") { continue }
        if (k == "timestamp") {
            // printf(v)
            let t = new Time("2006-01-02 15:04:05", v)
            // printf("%d",t.UnixMilli())
            obj["@timestamp"] = t.UnixMilli()
        }
        if (k == "categories" || k == "blockedCategories" || k == "AVDetections" || k == "PUAs" || k == "destinationListIDs") {
            fields[k] = decoder_CSV(v)
            continue
        }
        fields[k] = v
    }
    
    obj["@message"] = text // orig msg text
    obj["@opendnsProxy"] = fields
    obj["@parser"] = "fpl-CiscoUmbrella-proxylogs"
    obj["@parserVersion"] = "20240321-1"
    
    obj["@source"] = "opendnsProxy"
    obj["@sender"] = "opendnsProxy"
    obj["@event_type"] = "opendnsProxy"
    obj["@eventType"] = "CiscoUmbrellaProxyLogs"
    
    //obj["@customer"] = "<customer-name>"
    if(!obj["@timestamp"]){
        let t = new Time()
        obj["@timestamp"] = t.UnixMilli()
    }
    obj["@type"] = "event"
    
    // re-assign obj to doc
    doc.obj = obj
    return "pass"
}


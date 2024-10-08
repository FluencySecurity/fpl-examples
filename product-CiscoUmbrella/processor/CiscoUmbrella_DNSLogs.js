// Data input format: ({ obj, text, size }) or ( doc )
function main(doc) {
    // https://docs.umbrella.com/deployment-umbrella/docs/log-formats-and-versioning
    // https://docs.umbrella.com/deployment-umbrella/docs/dns-log-formats

    let csvKeyMap = {
        "0":"timestamp",
        "1":"policyIdentity",
        "2":"identities",
        "3":"internalIp",
        "4":"externalIp",
        "5":"action",
        "6":"queryType",
        "7":"responseCode",
        "8":"domain",
        "9":"categories",
        "10":"policyIdentityType",
        "11":"identityTypes",
        "12":"blockedCategories"
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
        if (k == "categories" || k == "blockedCategories") {
            fields[k] = decoder_CSV(v)
            continue
        }
        if (k == "domain") {
            fields[k+"_orig"] = v
            fields[k] = trim(v,".")
            continue
        }
        if (k == "policyIdentity") {
            fields[k] = v
            fields.username = removeParentheses(v)
            continue
        }
        fields[k] = v
    }
    
    obj["@message"] = text // orig msg text
    obj["@opendns"] = fields
    obj["@parser"] = "fpl-CiscoUmbrella-dnslogs"
    obj["@parserVersion"] = "20240322-2"
    
    obj["@source"] = "opendns"
    obj["@sender"] = "opendns"
    obj["@event_type"] = "opendns"
    obj["@eventType"] = "CiscoUmbrellaDNSLogs"
    
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

function removeParentheses(v) {
    let r = v
    let ch = indexOf(r, "(")
    if (ch > 1) {
        r = subString(r, 0, ch)
        r = trim(r," ")
    }
    return r
}

// Data input format: ({ obj, size, source }) or ( doc )

// https://support.catonetworks.com/hc/en-us/articles/9726441847965-Integrating-Cato-Events-with-AWS-S3

function main(envelop) {
    //
    let obj = envelop.obj

    let o = {}
    
    o["@cato"] = obj
    
    o["@event_type"] = "cato"
    o["@eventType"] = "CatoNetworks"
    o["@source"] = "events"
    o["@sender"] = "catonetworks"
    o["@type"] = "event"
    o["@parser"] = "fpl-CatoNetworksEvents"
    o["@parserVersion"] = "20240528-3"

    if(!o["@timestamp"]){
        //let t = new Time()
        //obj["@timestamp"] = t.UnixMilli()
        o["@timestamp"] = obj.time
    }
    envelop.obj = o
    return { status: "pass" }
}

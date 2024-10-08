// Description:
// Default system Syslog event passthrough

// Data input format: ({ obj, size }) or ( envelop )
//function main({obj, size}) {
    //
function main(envelop) {
    let obj = envelop.obj
    let size = envelop.size

    let o = {}
    o["@bst"] = obj.event
    
    if(o["@bst"].datetime){
        o["@timestamp"] = o["@bst"].datetime
    } else {
        let t = new Time()
        o["@timestamp"] = t.UnixMilli()
    }
    // geo-ip lookup for log_on events
    if(o["@bst"].event_name == "log_on" && o["@bst"].ip_source){
        try {
            let info = geoip(o["@bst"].ip_source)
            if (len(info)) {
                o["@bst"]["_ip"]=info
            }
        } catch (e) {
            obj["@parserError"] = "ip_source geoip failed"
        }
    }
    // flow normalization for network_connection events
    if(o["@bst"].event_name == "network_connection"){
        generateFusionEvent(o)
    }
    
    o["@event_type"] = "bst"
    o["@source"] = "telemetry"
    o["@sender"] = "bitdefender"
    o["@type"] = "event"
    o["@parser"] = "fpl-BitdefenderTelemetry"
    o["@parserVersion"] = "20240124-2"
    
    envelop.obj = o
    return { status: "pass" }
}

function generateFusionEvent(obj) {
    let f = obj["@bst"]

    if (!(f.ip_source && f.ip_dest && f.port_source && f.port_dest)) {
        // printf("invalid event record for flow: %v", f)
        return
    }

    let ts = obj["@timestamp"]

    let envelop = {
        partition: "default",
        dataType: "event",
        time_ms: ts
    }

    let sp = (f.port_source ? f.port_source : 0)
    let dp = (f.port_dest ? f.port_dest : 0)
    let prot = 0

    let dur = 0
    let sentP = 0
    let rcvdP = 0
    let sentB = (f.bytes_sent ? f.bytes_sent : 0)
    let rcvdB = (f.bytes_received ? f.bytes_received : 0)

    let source={
        flow: {
            sip: f.ip_source,
            dip: f.ip_dest,
            sp: sp,
            dp: dp,
            prot: prot,

            rxB: rcvdB,
            txB: sentB,
            totalB: sentB + rcvdB,
            rxP: rcvdP,
            txP: sentP,

            dur: dur,
            time_ms: ts
        },
        dtype:"network"
    }
    obj["@metaflow"] = source
    //printf("%v",source)
    Fluency_FusionEvent(envelop, source)
}


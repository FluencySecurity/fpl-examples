// Description:
// Default system Syslog event passthrough

// Data input format: ({ obj, size }) or ( envelop )
//function main({obj, size}) {
    //
function main(envelop) {
    let obj = envelop.obj
    let size = envelop.size

    let o = {}
    o["@bep"] = obj.event
    
    //if(o["@bst"].datetime){
    //    o["@timestamp"] = o["@bep"].datetime
    //} else {
        let t = new Time()
        o["@timestamp"] = t.UnixMilli()
    //}
    o["@event_type"] = "bep"
    o["@source"] = "eventpush"
    o["@sender"] = "bitdefender"
    o["@type"] = "event"
    o["@parser"] = "fpl-BitdefenderEventPush"
    
    envelop.obj = o
    return { status: "pass" }
}


// Description:
// Default system behavior event passthrough

// Data input format: ({ obj, size }) or ( doc )
function main(doc) {
    //
    let obj = doc.obj

    // Check for behaviorRule field
    if (!obj.behaviorRule && !obj.key){
        return { status: "abort" }
    }

    let o = {}
    o["@behaviorEvent"] = obj
    if(obj.timestamp){
        o["@timestamp"] = obj.timestamp
    } else {
        let t = new Time()
        o["@timestamp"] = t.UnixMilli()
    }
    o["@event_type"] = "behaviorEvent"

    o["@sender"] = "BehaviorEvent"
    o["@source"] = "BehaviorEvent"
    o["@type"] = "event"
    o["@parser"] = "fpl-behaviorevent"

    doc.obj = o
    return { status: "pass" }
}

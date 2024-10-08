// Description:
// Default system plugin event passthrough

// Data input format: ({ obj, size }) or ( doc )
function main({obj, size}) {
    //
    if(!obj["@timestamp"]){
        let t = new Time()
        obj["@timestamp"] = t.UnixMilli()
    }
    obj["@type"] = "event"
    obj["@parser"] = "fpl-plugin"
    return "pass"
}

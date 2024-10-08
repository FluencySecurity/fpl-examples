// Description:
// Default Sophos EDR API integration event adjustments

// Data input format: ({ obj, size }) or ( doc )
function main({obj, size}) {
    //
    if(!obj["@timestamp"]){
        let t = new Time()
        obj["@timestamp"] = t.UnixMilli()
    }
    obj["@type"] = "event"
    let f = obj["@sophos"]
    if (!f){
        return {"status":"abort"}
    }
    
    //obj["@event_type"] = "sophos"
    obj["@eventType"] = "SophosEDR"
    obj["@sender"] = "sophos"
    obj["@source"] = "sophos"
    obj["@parser"] = "fpl-SophosEDRAdjustments"
    obj["@parserVersion"] = "20240715-1"
    return {"status":"pass"}
}


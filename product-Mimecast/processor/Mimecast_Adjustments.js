// Description:
// Default Mimecast integration event adjustments

// Data input format: ({ obj, size }) or ( doc )
function main({obj, size}) {
    //
    if(!obj["@timestamp"]){
        let t = new Time()
        obj["@timestamp"] = t.UnixMilli()
    }
    obj["@type"] = "event"
    let f = obj["@fields"]
    if (!f){
        return {"status":"abort"}
    }
    
    // for /api/audit/get-audit-events
    let ei = f["eventInfo"]
    if (ei){
        
    }
    
    //obj["@event_type"] = "mimecast"
    obj["@eventType"] = "Mimecast"
    obj["@sender"] = "mimecast"
    obj["@source"] = "mimecast"
    obj["@parser"] = "fpl-MimecastAdjustments"
    obj["@parserVersion"] = "20240712-1"
    return {"status":"pass"}
}


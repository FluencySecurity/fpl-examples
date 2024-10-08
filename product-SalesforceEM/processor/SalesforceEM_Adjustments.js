// Description:
// Default Proofpoint integration event adjustments

// Data input format: ({ obj, size }) or ( doc )
function main({obj, size}) {
    //
    if(!obj["@timestamp"]){
        let t = new Time()
        obj["@timestamp"] = t.UnixMilli()
    }
    obj["@type"] = "event"
    
    obj["@event_type"] = "salesforce"
    obj["@eventType"] = "SalesforceEM"
    obj["@sender"] = "salesforce"
    obj["@source"] = "salesforce"
    obj["@parser"] = "fpl-SalesforceEMAdjustments"
    obj["@parserVersion"] = "20240711-1"
    return {"status":"pass"}
}

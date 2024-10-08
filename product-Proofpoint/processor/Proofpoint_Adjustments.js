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
    
    obj["@event_type"] = "proofpoint"
    obj["@eventType"] = "Proofpoint"
    obj["@sender"] = "proofpoint"
    obj["@source"] = "proofpoint"
    obj["@parser"] = "fpl-ProofpointAdjustments"
    obj["@parserVersion"] = "20240627-1"
    return {"status":"pass"}
}

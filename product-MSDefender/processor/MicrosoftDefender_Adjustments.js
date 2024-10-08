// Description:
// Default MS Defender integration event adjustments

// Data input format: ({ obj, size }) or ( doc )
function main({obj, size}) {
    //
    if(!obj["@timestamp"]){
        let t = new Time()
        obj["@timestamp"] = t.UnixMilli()
    }
    obj["@type"] = "event"
    
    //obj["@event_type"] = "defender"
    obj["@eventType"] = "MicrosoftDefender"
    obj["@sender"] = "defender"
    obj["@source"] = "defender"
    obj["@parser"] = "fpl-MSDefenderAdjustments"
    obj["@parserVersion"] = "20240718-1"
    return {"status":"pass"}
}

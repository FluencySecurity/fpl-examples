// Description:
// Default AWS CloudTrail integration event adjustments

// Data input format: ({ obj, size }) or ( doc )
function main({obj, size}) {
    //
    if(!obj["@timestamp"]){
        let t = new Time()
        obj["@timestamp"] = t.UnixMilli()
    }
    obj["@type"] = "event"
    obj["@sender"] = "aws"
    obj["@source"] = "cloudtrail"
    obj["@parser"] = "fpl-AWSCloudTrailAdjustments"
    obj["@parserVersion"] = "20240507-1"
    
    obj["@eventType"] = "AWSCloudTrail"
    obj["@event_type"] = "@cloudtrail"

    return { status: "pass" }
}

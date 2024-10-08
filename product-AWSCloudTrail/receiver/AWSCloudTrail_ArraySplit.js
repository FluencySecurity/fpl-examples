// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {
    //
    let records = obj.Records
    if (!records) {
        throw "No Records field in JSON obj"
    }
    // return obj.Records
    let list = []
    for i, fields = range records {
        let o = {}
        o["@type"] = "event"
        o["@parser"] = "fpl-CloudTrailArraySplit"
        let t = new Time(fields.eventTime)
        o["@timestamp"] = t.UnixMilli()
        o["@cloudtrail"] = fields
        o["@eventType"] = "AWSCloudTrail"
        o["@event_type"] = "@cloudtrail"
        o["@source"] = "cloudtrail"
   
        list = append(list, o)
    }
    return list
}


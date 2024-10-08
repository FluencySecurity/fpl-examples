// Description:
// Syslog CEF from Varonis Data Protection

// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {
    // Event selection criteria
    let msg = obj["@message"]
    if (!msg){
        return {"status":"abort"}
    }
    let tags = obj["@tags"]
    if (!tags) {
        return {"status":"abort"}
    }

    if (startsWith(msg, "0|Varonis") && tags.Some( (_, tag) => startsWith(tag, "CEF" ))){
       // Varonis CEF events
    } else {
       return {"status":"abort"}
    }

    // Output field settings
    obj["@type"] = "event"

    obj["@parser"] = "fpl-VaronisCEFSyslog"
    obj["@parserVersion"] = "20241007-2"
    obj["@event_type"]="varonis" // event_type for interface compatibility
    obj["@eventType"]="Varonis" // eventType for display purposes

    // Event parsing
    let m = mergeTagColonWithMessage(obj)
    let f = decoder_CEF(m)

    obj["@varonis"] = f
    //tags = ["varonis"]
    //obj["@tags"] = tags

    // Discard original message
    //obj["@message"] = ""

    // Collect device metrics
    recordDeviceMetrics(obj, size)

    return {"status":"pass"}
}


function mergeTagColonWithMessage(obj) {
    let tags = obj["@tags"]
    if(tags){
        return tags[0] + ":" + obj["@message"]
    }
    return obj["@message"]
}

function recordDeviceMetrics(obj, size) {
    let sender = obj["@sender"]
    let source = obj["@source"]

    let deviceName = source

    let deviceEntry = Fluency_Device_LookupName(deviceName)
    if (!deviceEntry) {
        deviceEntry = {
            name:deviceName,
            ips: [sender],
            group:"FPL-detect: Varonis",
            device: {
                name:"Varonis",
                category:"Data Protection"
            }
        }
        Fluency_Device_Add(deviceEntry)
    }
    let dimensions = {
        namespace:"fluency",
        app:"import",
        eventType:"Varonis",
        syslogSender:sender,
        customer: "default",
        importSource: deviceEntry.name,
        deviceType: deviceEntry.device.name
    }
    if (deviceEntry.group) {
        dimensions.group = deviceEntry.group
    }
    Platform_Metric_Counter("fluency_import_count", dimensions, 1)
    Platform_Metric_Counter("fluency_import_bytes", dimensions, size)
}

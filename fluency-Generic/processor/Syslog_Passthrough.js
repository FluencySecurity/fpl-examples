// Processor Name:
// Syslog_Passthrough
// Description:
// Template: Default system Syslog event passthrough 

// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {
    //
    obj["@type"] = "event"
    if (source && source != "" ) {
        obj["@collector"] = source
    } else {
        obj["@collector"] = "fluency-server" // server side syslog collector ('local')
    }
    obj["@parser"] = "fpl"

    recordDeviceMetrics(obj, size)

    return { status: "pass" }
}
function recordDeviceMetrics(obj, size) {
    let sender = obj["@sender"]
    let source = obj["@source"]
    
    if (len(source) > 80) {
        return // reject if source name too long
    }
    
    let internal = Fluency_EntityinfoCheck("HOME_NET", sender)
    if (!internal) {
      return // reject if source ip is not internal address
    }

    let deviceName = "Syslog - " + source

    let deviceEntry = Fluency_Device_LookupName(deviceName)
    if (!deviceEntry) {
        deviceEntry = {
            name:deviceName,
            ips: [sender],
            group:"FPL-detect: Generic Syslog (un-parsed)",
            device: {
                name:"Generic Device",
                category:"Unknown"
            }
        }
        Fluency_Device_Add(deviceEntry)
    }
    let dimensions = {
        namespace:"fluency",
        app:"import",
        eventType:"GenericSyslog",
        syslogSender:sender,
        customer: "default",
        importSource: deviceEntry.name,
        deviceType: deviceEntry.device.name
    }
    if deviceEntry.group {
        dimensions.group = deviceEntry.group
    }
    Platform_Metric_Counter("fluency_import_count", dimensions, 1)
    Platform_Metric_Counter("fluency_import_bytes", dimensions, size)
}

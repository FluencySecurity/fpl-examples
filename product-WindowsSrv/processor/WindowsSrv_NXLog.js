// Description:
// Selects / parses Windows NXLog records w/ (merge_tag_colon_with_message)

// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {
    // Replacement for Java (Groovy) parser
    let tags = obj["@tags"]
    if (!tags) {
        return { status: "abort" }
    }
    if (tags.Some((_, tag) =>  (tag !=`{"EventTime"` && tag !=`{"EventReceivedTime"`))) {
        return { status: "abort" }
    }
    
    let m = merge_tag_colon_with_message(obj)
    // printf("%s",m)
    if (!startsWith(m,"{")) {
        obj["@parserError"] = "Invalid JSON message (no '{')"
        // printf("debug")
        // printf("%s",m)
        return { status: "abort" }
    }

    obj["@type"] = "event"
    obj["@parser"] = "fpl-WindowsNXLog"
    obj["@parserVersion"] = "20240321-2"

    let f = {}

    try {
        let p = parseJson(m)
        if (!p) {
            obj["@tags"] = ["_jsonParseError"]
            obj["@parserError"] = "No object after parseJson()"
            return { status: "pass" }
        }
        f = p
    } catch (e) {
        obj["@parserError"] = sprintf("(%s) - %s", e.name, e.message)
        return { status: "pass" }
    }
    
    if (f.LogonProcessName) {
        f.LogonProcessName = trimSpace(f.LogonProcessName)
    }
    if (f.TargetUserName && f.TargetDomainName){
        f._TargetFullName_ = f.TargetUserName + "\\" + f.TargetDomainName
    }
    if (f.SubjectUserName && f.SubjectDomainName){
        f._SubjectFullName_ = f.SubjectUserName + "\\" + f.SubjectDomainName
    }

    if (f.SourceModuleType == "im_msvistalog") {
        if (f.EventType) {
            // set tags to eventType
            obj["@tags"] = [f.EventType]
        }
        obj["@eventType"] = "nxlogAD"
    }
    
    if (f.SourceModuleType == "im_internal") {
        obj["@tags"] = [f.SourceName]
        obj["@eventType"] = "nxlog"
    }
    
    if (f.SourceModuleType == "im_file") {
        obj["@tags"] = [f.SourceModuleName]
        obj["@eventType"] = "nxlogFile"
    }

    if (f.SourceModuleName=="dhcp_in") {
        //printf("dhcp nested")
        let segments = split(f.Message,",")
        //printf("%v",len(segments))
        if (len(segments) < 7) {
            // return {"status":"reject","msg":"dhcp msg too short"}
            obj["@parserError"] = "DHCP message too short"
            return { status: "pass" }
        }
        f.Type = segments[3]
        f.ClientIp = segments[4]
        f.Hostname = segments[5]
        f.ClientMac = segments[6]
        f.EventType = segments[0]
        obj["@tags"] = ["windows-dhcp"]
        obj["@eventType"] = "nxlogDHCP"
    }

    // message replacement
    if (f.Message) {
        obj["@message"] = f.Message
        delete(f, "Message")
    } else {
        // use original message instead
        obj["@parserError"] = "No Message in JSON object"
    }
    
    // original msg (debug)
    // obj["@msg"] = m

    obj["@fields"] = f

    // Event drop criteria
    let eid = f.EventID
    let pn = f.ProcessName
    if(eid == 5152 || eid == 5156 || eid == 5157 || eid == 5158){
        //recordDropppedMetrics(obj, size)
        return { status: "drop" }
    }
    if(eid == 4656 || eid == 4658){
        //recordDropppedMetrics(obj, size)
        return { status: "drop" }
    }
    if(eid == 4661 || eid == 4662 || eid == 4663 || eid == 4690){
        //if (contains(pn, "avtar.exe")){ // "C:\\Program Files\\avs\\bin\\avtar.exe"
            //recordDropppedMetrics(obj, size)
        //}
        return { status: "drop" }
    }

    // device name
    if (obj["@eventType"] == "nxlogAD"){
        let deviceName = (f.Hostname ? f.Hostname : "unknown")
        recordDeviceMetrics(obj, size, deviceName)
    }

    return { status: "pass" }
}

function processJSON(o) {
    if (o.LogonProcessName) {
        o.LogonProcessName = trimSpace(o.LogonProcessName)
    }
    if (o.TargetUserName && o.TargetDomainName){
        o._TargetFullName_ = o.TargetUserName + "\\" + o.TargetDomainName
    }
    if (o.SubjectUserName && o.SubjectDomainName){
        o._SubjectFullName_ = o.SubjectUserName + "\\" + o.SubjectDomainName
    }
    return o
}

function merge_tag_colon_with_message(obj) {
    let tags = obj["@tags"]
    if(tags){
        return tags[0] + ":" + obj["@message"]
    }
    return obj["@message"]
}

function recordDeviceMetrics(obj, size, deviceName) {
    let sender = obj["@sender"]
    let source = obj["@source"]

    let deviceEntry = Fluency_Device_LookupName(deviceName)
    if (!contains(deviceName, ".")) { // avoid second device entry
        deviceEntry = Fluency_Device_Lookup(sender)
    }
    if (!deviceEntry) {
        deviceEntry = {
            name:deviceName,
            ips: [sender],
            group:"FPL-detect: Windows Application Server",
            device: {
                name:"Windows Application Server",
                category:"Application Server"
            }
        }
        Fluency_Device_Add(deviceEntry)
    }
    let dimensions = {
        namespace:"fluency",
        app:"import",
        eventType:"WindowsNXLog",
        syslogSender:sender,
        // syslogDevice:deviceEntry.name,
        customer: "default",
        importSource: deviceEntry.name,
        deviceType: deviceEntry.device.name
    }
    if (deviceEntry.group) {
        dimensions.group = deviceEntry.group
    }
    Platform_Metric_Counter("fluency_import_count", dimensions,1)
    Platform_Metric_Counter("fluency_import_bytes", dimensions,size)
}
/*
function recordDropppedMetrics(obj, size) {
    let f = obj["@fields"]

    let dimensions = {
        EventID: f.EventID,
        Hostname: f.Hostname,
        Channel: f.Channel,
        Category: f.Category,
        // SubjectFullName: f._SubjectFullName_,
        // TargetFullName: f._TargetFullName_,
        SourceName: f.SourceName
    }

    Platform_Metric_Counter("WindowsNXLog_count", dimensions,1)
    Platform_Metric_Counter("WindowsNXLog_bytes", dimensions,size)
}
*/

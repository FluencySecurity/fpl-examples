// Description:
// Syslog (Event/Traffic logs) from Check Point Firewalls

// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {
    // Event selection criteria
    let msg = obj["@message"]
    if (!msg){
        return {"status":"abort"}
    }

    let tags = obj["@tags"]
    if (!(tags && tags.Some( (_, tag) =>  tag =="1" ))) {
        return {"status":"abort"}
    }

    let s = indexOf(msg, " [") 
    if (s < 0) {
        return {"status":"abort"}
    }
    let header = subString(msg, 0, s)    
    let header_fields = split(header, " ")
    if (!(len(header_fields)>2 && "CheckPoint" == header_fields[2])) {
        return {"status":"abort"}
    }

    // Output field settings
    obj["@type"] = "event"

    obj["@parser"] = "fpl-CheckPointFW"
    obj["@parserVersion"] = "20240320-5"
    obj["@event_type"]="checkpoint"
    obj["@eventType"]="CheckPoint"

    // Event parsing
    let f = {}
    if (len(header_fields)>1) {
        f.device_name = header_fields[1]
    }
    // remove header
    msg = subString(msg, s+2, len(msg)-1)
    
    // Check if starts with Fields and remove it if needed
    if (startsWith(msg, "Fields")) {
        s = indexOf(msg, " ")
        msg = subString(msg, s+1, len(msg))
        // uses ' ' as fields delimiter
        f = decoder_MixedKeyValue(msg)
    } else {
        // uses ; as fields delimiter
        let fields = split(msg, "\";")
        for (let i = 0; i < len(fields); i++) {
            let keyValue = split(fields[i], ":\"")
            let key = trim(keyValue[0], " ")
            let value = trim(keyValue[1], "\"")
            f[key] = value
        }
    }
    if (f.src) {
        let sgeoip = geoip(f.src)
        if (len(sgeoip)>0) {
            f["src_geoip"] = sgeoip
        }
    }
    if (f.dst) {
        let dgeoip = geoip(f.src)
        if (len(dgeoip)>0) {
            f["dst_geoip"] = dgeoip
            // backwards compatibility
            f["_ip"] = dgeoip
        }
    }
    // normalize username
    if (f["src_user_name"]) {
        f.username = trim(f["src_user_name"], "()")
    }

    obj["@checkpoint"] = f
    obj["@tags"] = ["checkpoint"]
    if (f.product) {
        obj["@tags"] = append(obj["@tags"],f.product)
    }

    // Collect device metrics
    recordDeviceMetrics(obj, size)

    // Metaflow, data normalization
    generateFusionEvent(obj)

    return {"status":"pass"}
}

function generateFusionEvent(obj) {
    let f = obj["@checkpoint"]

    if (!(f.src && f.dst && f.service && f.proto)) { // data may not have s_port field
    // if (!(f.src && f.dst && f.s_port && f.service && f.proto)) {
        // printf("invalid event record for flow: %v", f)
        return
    }

    let ts = obj["@timestamp"]

    let envelop = {
        partition: "default",
        dataType: "event",
        time_ms: ts
    }

    let sp = (f.s_port ? parseInt(f.s_port) : 0)
    let dp = (f.service ? parseInt(f.service) : 0)
    let prot = (f.proto ? parseInt(f.proto) : 0)

    let dur = (f.duration ? parseInt(f.duration) : 0)
    let sentP = (f.client_outbound_packets ? parseInt(f.client_outbound_packets) : 0)
    let rcvdP = (f.client_inbound_packets ? parseInt(f.client_inbound_packets) : 0)
    let sentB = (f.client_outbound_bytes ? parseInt(f.client_outbound_bytes) : 0)
    let rcvdB = (f.client_inbound_bytes ? parseInt(f.client_inbound_bytes) : 0)

    let source={
        flow: {
            sip: f.src,
            dip: f.dst,
            sp: sp,
            dp: dp,
            prot: prot,

            rxB: rcvdB,
            txB: sentB,
            totalB: sentB + rcvdB,
            rxP: rcvdP,
            txP: sentP,

            dur: dur,
            time_ms: ts
        },
        dtype:"checkpoint"
    }
    
    if (f.action == "Drop" || f.action == "Block"){
        source.flags = ["fwdeny"]
    }
    
    let meta = { mt:"checkpoint" }
        
    if(f.user && f.user != "") {
        meta.user = trim(f.user," ")
    }
    if(f.src_user_name && f.src_user_name != "") {
        meta.su = trim(f.src_user_name," ")
    }
    if(f.src_machine_name && f.src_machine_name != "") {
        meta.s_asset = { hostname:trim(f.src_machine_name," ") }
    }
    if(f.dst_machine_name && f.dst_machine_name != "") {
        meta.d_asset = { hostname:trim(f.dst_machine_name," ") }
        if(f.dst_user_name && f.dst_user_name != "") {
            meta.du = trim(f.dst_user_name," ")
        }
    }
    if(f.appi_name && f.appi_name != "") {
        if (indexOf(f.appi_name, " ")<0 && !isValidIP(f.appi_name)) {
            meta.url = f.appi_name
        }
    }
    if (f.product == "New Anti Virus") {
        if (f.action){
            let alert = {
                sid:"checkpoint_malware_action",
                classification:"checkpoint",
                action:f.action,
            }
            if(f.protection_name && f.protection_name != "") {
                if(f.malware_action && f.malware_action != "") {
                    alert.msg = f.malware_action + " - " + f.protection_name
                    alert.malware_action = f.malware_action
                } else {
                    alert.msg = f.protection_name
                }
                alert.malware_name = f.protection_name
            }
            if(f.severity && f.severity != "") {
                alert.severity = f.severity
            }
            if(f.protection_type && f.protection_type != "") {
                alert.malware_type = f.protection_type
            }
            if(f.malware_family && f.malware_family != "") {
                alert.malware_family = f.malware_family
            }
            if(f.policy && f.policy != "") {
                alert.policy = f.policy
            }
            if(f.severity && f.severity != "") {
                alert.severity = f.severity
            }
            source.alerts = [alert]
        }
    }
    
    if (len(meta) > 1) {
        source.meta = [meta]
    } else {
        //printf("no meta info")
    }
    
    obj["@metaflow"] = source
    //printf("%v",source)
    Fluency_FusionEvent(envelop, source)
}

function recordDeviceMetrics(obj, size) {
    let sender = obj["@sender"]
    let source = obj["@source"]
    let f = obj["@checkpoint"]

    let deviceName = (f.device_name ? f.device_name : "unknown")

    let deviceEntry = Fluency_Device_LookupName(deviceName)
    if (!deviceEntry) {
        deviceEntry = {
            name:deviceName,
            ips: [sender],
            group:"FPL-detect: Check Point NGFW",
            device: {
                name:"CheckPoint NGFW",
                category:"Firewall"
            }
        }
        Fluency_Device_Add(deviceEntry)
    }
    let dimensions = {
        namespace:"fluency",
        app:"import",
        eventType:"CheckPoint",
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

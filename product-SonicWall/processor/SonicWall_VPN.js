// Description:
// Syslog (Event/Traffic logs) from SonicWall VPNs

// {
//  "@message": "id=sslvpn sn=1SN2345678 time=\"2023-10-30 17:02:28 UTC\" vp_time=\"2024-03-03 12:07:31 UTC\" fw=10.1.200.254 pri=5 m=34 c=402 src=123.45.67.89 msg=\"WAF threat prevented: SQL Injection Attack\" URI=50.226.68.158:443/cgi-bin/extendauthentication rule-match=\"",
//  "@facility": "local0"
// }

// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {

    let msg = obj["@message"]
    if (!msg){
        return {"status":"abort"}
    }
    
    if (!startsWith(msg, "id=")){
        return {"status":"abort"}
    }
    let tags = obj["@tags"]
    if (!tags) {
        return {"status":"abort"}
    }
    if (!tags.Some( (_, tag) => tag == "SSLVPN" )) {
        return {"status":"abort"}
    }

    obj["@type"] = "event"

    obj["@parser"] = "fpl-SonicWallVPNSyslog"
    obj["@parserVersion"] = "20240303-1"
    
    let f = decoder_MixedKeyValue(msg)
    
    obj["@event_type"]="sonicwall"
    obj["@eventType"]="SonicWallVPN"
    obj["@sonicwall"] = f
    
    sonicwallFieldAdjustments(f)

    // tags = ["sonicwall"]
    if (f.msg == "SSL VPN zone remote user login allowed"){
        tags = append(tags, "vpnlogin")
    }
    tags = append(tags, "sonicwall")
    obj["@tags"] = tags

    // device name
    let deviceName = (f.sn ? f.sn : "unknown")
    recordDeviceMetrics(obj, size, deviceName)

    return {"status":"pass"}
}

function parseProto(proto) {
    if (startsWith(proto, "tcp")) {
        return 6
    } elseif (startsWith(proto, "udp")) {
        return 17
    } elseif (startsWith(proto, "icmp")) {
        return 1
    } elseif (startsWith(proto, "igmp")) {
        return 2
    } elseif (startsWith(proto, "icmpv6") || startsWith(proto, "icmp6")) {
        return 6
    }
    return 0
}

function sonicwallFieldAdjustments(doc) {
    let srcValue = doc.src
    if (srcValue) {
        let results = geoip(srcValue)
        if (results && results.countryCode ){
        } else {
            results = {country: "Unknown", city: "Unknown", org: "Unknown", isp: "Unknown", countryCode: "--"}
        }
        doc._ip=results
    }
    let dstValue = doc.dst
    if (dstValue) {
        let dd = split(dstValue, ":")
        if (len(dd) > 1) {
            doc.dip = dd[0]
            doc.dp = parseInt(dd[1])
        }
    }
    doc.protocol = parseProto(doc.proto)
    
    doc.rcvd = parseInt(doc.rcvd)
    doc.sent = parseInt(doc.sent)
    doc.rpkt = parseInt(doc.rpkt)
    doc.spkt = parseInt(doc.spkt)

    return doc
}

function recordDeviceMetrics(obj, size, deviceName) {
    let sender = obj["@sender"]
    let source = obj["@source"]

    let deviceEntry = Fluency_Device_LookupName(deviceName)
    if (!deviceEntry) {
        deviceEntry = {
            name:deviceName,
            ips: [sender],
            group:"FPL-detect: SonicWall VPN",
            device: {
                name:"SonicWall VPN",
                category:"Firewall"
            }
        }
        Fluency_Device_Add(deviceEntry)
    }
    let dimensions = {
        namespace:"fluency",
        app:"import",
        eventType:"SonicWallNGFW",
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

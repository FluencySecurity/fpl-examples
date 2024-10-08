// Description:
// Syslog (Event/Traffic logs) from Sophos Firewalls

// Sophos UTM: Packet filter log files
// https://support.sophos.com/support/s/article/KB-000034242?language=en_US

// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {
  // event selection criteria
  let msg = obj["@message"]
  if (!msg){
    return {"status":"abort"}
  }
  
  let tags = obj["@tags"]
  if (!tags) {
      return {"status":"abort"}
  }
  if (!tags.Some( (_, tag) => ( len(tag) == 4 && startsWith(tag, "20" )))) {
    return {"status":"abort"}
  }
  let s = indexOf(msg, "]: ") 
  if (s < 0) {
    return {"status":"abort"}
  }
  
  // event parsing
  let device_name = ""
  if (s >= 0) {
    let sp = split(subString(msg, 0, s+2), " ")
    // printf("%s",sp[1])
    if (len(sp) < 2) { // too short
      return {"status":"abort"}
    }
    device_name = sp[1]
    msg = subString(msg, s+2, len(msg))
  }
  
  // check if ether type is present and if the value is encoded with quotes
  let f = decoder_MixedKeyValue(msg)

  // output field settings
  obj["@type"] = "event"

  obj["@parser"] = "fpl-SophosUTMSyslog"
  obj["@tags"] = ["sophos"]
  obj["@parserVersion"] = "20240305-1"
  obj["@event_type"]="sophos"
  obj["@eventType"]="SophosUTM"

  if (len(device_name) > 0){
    f.device_name = device_name
  }

  obj["@sophos"] = f
  
  // Collect device metrics
  recordDeviceMetrics(obj, size)

  // Metaflow, data normalization
  // generateFusionEvent(obj)
  return {"status":"pass"}
}

function recordDeviceMetrics(obj, size) {
    let sender = obj["@sender"]
    let source = obj["@source"]
    let f = obj["@sophos"]

    let deviceName = (f.device_name ? f.device_name : "unknown")

    let deviceEntry = Fluency_Device_LookupName(deviceName)
    if (!deviceEntry) {
        deviceEntry = {
            name:deviceName,
            ips: [sender],
            group:"FPL-detect: Sophos UTM Firewall",
            device: {
                name:"Sophos UTM",
                category:"Firewall"
            }
        }
        Fluency_Device_Add(deviceEntry)
    }
    let dimensions = {
        namespace:"fluency",
        app:"import",
        eventType:"SophosUTM",
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
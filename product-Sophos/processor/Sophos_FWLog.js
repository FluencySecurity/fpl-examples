// Description:
// Syslog (Event/Traffic logs) from Sophos Firewalls

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
  // device= or device_name=
  if (!tags.Some( (_, tag) => ( startsWith(tag, "device" )))) {
    return {"status":"abort"}
  }
  
  if (!(startsWith(msg, "date=") || (startsWith(msg, "timestamp=")))) {
    return {"status":"abort"}
  }
  
  // event parsing
  let m = mergeTagWithMessage(obj)
  
  // check if ether type is present and if the value is encoded with quotes
  if (indexOf(m, "ether_type") > 0) {
    if (indexOf(m, "ether_type=\"") < 0) {
      m = replaceAll(m, "ether_type=(?P<Value>[a-zA-Z0-9]+) (?P<IP>[a-zA-Z0-9()]+)", "ether_type=\"${1}${2}\"", -1)
    }
  }
  
  let f = decoder_MixedKeyValue(m)

  // output field settings
  obj["@type"] = "event"

  obj["@parser"] = "fpl-SophosFWSyslog"
  obj["@tags"] = ["sophos"]
  obj["@parserVersion"] = "20240305-4"
  obj["@event_type"]="sophos"
  obj["@eventType"]="Sophos"

  obj["@sophos"] = f
  
  // Collect device metrics
  recordDeviceMetrics(obj, size)

  // Metaflow, data normalization
  // generateFusionEvent(obj)
  return {"status":"pass"}
}

function mergeTagWithMessage(obj) {
    let tags = obj["@tags"]
    if(tags){
        return tags[0] + " " + obj["@message"]
    }
    return obj["@message"]
}

function recordDeviceMetrics(obj, size) {
    let sender = obj["@sender"]
    let source = obj["@source"]
    let f = obj["@sophos"]

    let deviceName = (f.device_id ? f.device_id : "unknown")
    if (deviceName == "unknown") {
        deviceName = (f.device_serial_id ? f.device_serial_id : "unknown")
    }

    let deviceEntry = Fluency_Device_LookupName(deviceName)
    if (!deviceEntry) {
        deviceEntry = {
            name:deviceName,
            ips: [sender],
            group:"FPL-detect: Sophos Firewall",
            device: {
                name:"Sophos Firewall",
                category:"Firewall"
            }
        }
        Fluency_Device_Add(deviceEntry)
    }
    let dimensions = {
        namespace:"fluency",
        app:"import",
        eventType:"Sophos",
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
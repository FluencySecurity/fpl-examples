// Cisco Secure Firewall Threat Defense Syslog Messages

// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {
  // Event selection criteria
  let msg = obj["@message"]
  if (!msg){
    return "abort"
  }  
  if (!startsWith(msg, "%FTD") && !startsWith(msg, "%ASA")) {
    msg = merge_tag_colon_with_message_v2(obj)
    // try match again
    if (!startsWith(msg, "%FTD") && !startsWith(msg, "%ASA")) {
        return "abort"
    }
  }
  
  // Event parsing
  let s = indexOf(msg, ": ")
  let header = subString(msg, 0, s)
  msg = subString(msg, s + 2, len(msg))
  header = regexp("-(?P<msg_type>[0-9])-(?P<fid>[0-9]+)", header)
  let msg_type_map = {
    "1": "Alert",
    "2": "Critical",
    "3": "Error",
    "4": "Warning",
    "5": "Notification",
    "6": "Informational",
    "7": "Debugging"
  }
  let fid = header.fid
  let f = processMSG(msg, fid)
  if (isNull(f)) {
      f = {}
      f["error"] = "Unknown Syslog message ID"
  }
  f["fid"] = "ASA-" + fid
  f["msg_type"] = msg_type_map[header.msg_type]
  
  // Output field settings
  obj["@type"] = "event"

  obj["@parser"] = "fpl-CiscoASAParser"
  obj["@parserVersion"] = "20240918-1"
  obj["@eventType"]="CiscoASA"
  
  obj["@fields"] = f
  
  obj["@tags"] = ["ASA",f["fid"]]
  
  return "pass"
}

function processMSG(msg, fid) {
  let asaMap = {
    "106001": (m) => asa106001(m),
    "106006": (m) => asa106006(m),
    "106007": (m) => asa106007(m),
    "106010": (m) => asa106010(m),
    "106012": (m) => asa106012(m),
    "106014": (m) => asa106014(m),
    "106015": (m) => asa106015(m),
    "106021": (m) => asa106021(m),
    "106022": (m) => asa106021(m),
    "106023": (m) => asa106023(m),
    "106100": (m) => asa106100(m),
    "106103": (m) => asa106103(m),
    "109201": (m) => asa109201to109213(m),
    '109202': (m) => asa109201to109213(m),
    "109203": (m) => asa109201to109213(m),
    "109204": (m) => asa109201to109213(m),
    "109205": (m) => asa109201to109213(m),
    "109206": (m) => asa109201to109213(m),
    "109207": (m) => asa109201to109213(m),
    "109208": (m) => asa109201to109213(m),
    "109209": (m) => asa109201to109213(m),
    "109210": (m) => asa109201to109213(m),
    "109211": (m) => asa109201to109213(m),
    "109212": (m) => asa109201to109213(m),
    "109213": (m) => asa109201to109213(m),
    "110002": (m) => asa110002(m),
    "113003": (m) => asa113003(m),
    "113004": (m) => asa113004(m),
    "113005": (m) => asa113005(m),
    "113008": (m) => asa113008(m),
    "113009": (m) => asa113009(m),
    "113010": (m) => asa113010(m),
    "113011": (m) => asa113009(m),
    "113019": (m) => splitByEq(m),
    "113039": (m) => asa113039(m),
    "430002": (m) => splitByEq(m),
    "430003": (m) => splitByEq(m)
  }
  if (asaMap[fid]) {
    return run(asaMap[fid], msg)
  }
  return null
}

// Event parsing functions by the Event ID
function asa106001(msg) {
  let obj = regexp("from (?P<src_ip>[^/]+)/(?P<src_port>.*) to (?P<dst_ip>[^/]+)/(?P<dst_port>.*) flags (?P<tcp_flags>.*) on interface (?P<interface>.*)", msg)
  obj.action = "Deny"
  obj.protocol = "inbound TCP connection"
  return obj
}
function asa106006(msg) {
  let obj = regexp("from (?P<src_ip>[^/]+)/(?P<src_port>.*) to (?P<dst_ip>[^/]+)/(?P<dst_port>.*) flags (?P<tcp_flags>.*) on interface (?P<interface>.*)", msg)
  obj.action = "Deny"
  obj.protocol = "inbound UDP"
  return obj
}
function asa106007(msg) {
  let obj = regexp("from (?P<src_ip>[^/]+)/(?P<src_port>.*) to (?P<dst_ip>[^/]+)/(?P<dst_port>.*) flags (?P<tcp_flags>.*) due to (?P<reason>.*)", msg)
  obj.action = "Deny"
  obj.protocol = "inbound UDP"
  return obj
}
function asa106010(msg) {
  let obj = regexp("Deny (?P<protocol>.*) src (?P<src_interface>[^:]+):(?P<src_ip>[^/]+)/(?P<src_port>.*) dst (?P<dst_interface>[^:]+):(?P<dst_ip>[^/]+)/(?P<dst_port>.*)", msg)
  obj.action = "Deny"
  return obj
}
function asa106012(msg) {
  let obj = regexp("from (?P<src_ip>.*) to (?P<dst_ip>.*), IP options: (?P<ip_options>.*)", msg)
  obj.ip_options = trim(obj.ip_options, "\"")
  return obj
}
function asa106014(msg) {
  let obj = regexp("src (?P<src_interface>[^:]+):(?P<src_ip>[^/]+)/(?P<src_port>.*) dst (?P<dst_interface>[^:]+):(?P<dst_ip>[^/]+)/(?P<dst_port>.*)", msg)
  obj.action = "Deny"
  obj.protocol = "inbound icmp"
  return obj
}
function asa106015(msg) {
  let obj = regexp("from (?P<src_ip>[^/]+)/(?P<src_port>.*) to (?P<dst_ip>[^/]+)/(?P<dst_port>.*) flags (?P<tcp_flags>.*) on interface (?P<interface>.*)", msg)
  obj.action = "Deny"
  obj.protocol = "TCP (no connection)"
  return obj
}
function asa106021(msg) {
  let obj = regexp("from (?P<src_ip>.*) to (?P<dst_ip>.*) on interface (?P<interface>.*)", msg)
  obj.action = "Deny"
  return obj
}
function asa106023(msg) {
  let obj = regexp("Deny (?P<protocol>.*) src (?P<src_interface>[^:]+):(?P<src_ip>.*) dst (?P<dst_interface>[^:]+):(?P<dst_ip>.*) by access-group \"(?P<access_group>.*)\" (?P<codes>.*)", msg)
  let codes = split(obj.codes, ", ")
  obj.hashcode1 = trim(codes[0], "[")
  obj.hashcode2 = trim(codes[1], "]")
  obj.result = "Deny"
  delete(obj, "codes")
  return obj
}
function asa106100(msg) {
  let obj = regexp("access-list (?P<policy_id>\\S+) (?P<action>\\S+) (?P<protocol>\\S+) (?P<src_interface>[^/]+)/(?P<src_address>.*) -> (?P<dst_interface>[^/]+)/(?P<dst_address>.*) hit-cnt (?P<hit_count>[0-9]+) (?P<interval>[^[]+) (?P<codes>.*)", msg)
  let codes = split(obj.codes, ", ")
  obj.hashcode1 = trim(codes[0], "[")
  obj.hashcode2 = trim(codes[1], "]")
  delete(obj, "codes")
  obj.src_port = trim(split(obj.src_address, "(")[1], ")")
  obj.src_address = split(obj.src_address, "(")[0]
  obj.dst_port = trim(split(obj.dst_address, "(")[1], ")")
  obj.dst_address = split(obj.dst_address, "(")[0]
  if (match(obj.interval, "first hit")) {
    delete(obj, "interval")
  } else {
    obj.interval = split(obj.interval, "-")[0]
  }
  return obj
}
function asa106103(msg) {
  let obj = regexp("access-list (?P<policy_id>\\S+) (?P<action>\\S+) (?P<protocol>\\S+) for user '(?P<user>.*)' (?P<src_interface>[^/]+)/(?P<src_ip>[^(]+)(?P<src_port>.*) -> (?P<dst_interface>[^/]+)/(?P<dst_ip>[^(]+)(?P<dst_port>.*) hit-cnt (?P<hit_count>[0-9]+) first hit (?P<codes>.*)", msg)
  let codes = split(obj.codes, ", ")
  obj.hashcode1 = trim(codes[0], "[")
  obj.hashcode2 = trim(codes[1], "]")
  delete(obj, "codes")
  obj.src_port = trim(obj.src_port, "()")
  obj.dst_port = trim(obj.dst_port, "()")
  return obj
}
function asa109201to109213(msg) {
  return regexp("Session=(?P<session>.*), User=(?P<user>.*), Assigned IP=(?P<ip>.*), (?P<action>.*)", msg)
}
function asa110002(msg) {
  return regexp("(?P<action>.*) for (?P<protocol>.*) from (?P<src_interface>[^:]+):(?P<src_ip>[^/]+)/(?P<src_port>.*) to (?P<dst_ip>[^/]+)/(?P<dst_port>.*)", msg)
}
function asa113003(msg) {
  // not very important
  let obj = regexp("user (?P<user>.*) is being set to (?P<policy_name>.*)", msg)
  obj.action = "Group policy update to user policy"
  return obj
}
function asa113004(msg) {
  let obj = regexp("user (?P<operation>.*) Successful : server = (?P<server>.*) : user = (?P<user>.*)", msg)
  obj.server_ip = trim(obj.server_ip, " ")
  obj.action = "Successful"
  return obj
}
function asa113005(msg) {
  let obj = regexp("server = (?P<server>.*) : user = (?P<user>.*) : user IP = (?P<src_ip>.*)", msg)
  obj.action = "Rejected authentication"
  obj.reason = "AAA failure"
  return obj
}
function asa113008(msg) {
  let obj = regexp("user = (?P<user>.*)", msg)
  obj.action = "Accept transaction"
  return obj
}
function asa113009(msg) {
  let obj = regexp("policy (?P<policy>.*) for user = (?P<user>.*)", msg)
  obj.policy = trim(obj.policy, "()")
  return obj
}
function asa113010(msg) {
  return regexp("user (?P<user>.*) from server (?P<server>.*).", msg)
}
function asa113039(msg) {
  return regexp("Group <(?P<group>.*)> User <(?P<user>.*)> IP <(?P<ip>.*)> AnyConnect", msg)
}
function splitByEq(msg) {
  let obj = {}
  let fields = split(msg, ",")
  for (let i = 0; i < len(fields); i++) {
    let parts = split(fields[i], "=")
    if (len(parts) >  1) {
      let key = trim(parts[0], " ")
      let value = trim(parts[1], " ")
      obj[key] = value
    }
  }
  return obj
}
function merge_tag_colon_with_message_v2(obj) {
  let tags = obj["@tags"]
  if(tags){
      return tags[0] + ": " + obj["@message"]
  }
  return obj["@message"]
}

// Description:
// Template: A Sample FPL Processor file

// Fluency Platform architecture
// - hypothetical location of "A Sample Processor" in a typical architecture
//
//                 --------------------------------------
//                 |[router (ExampleRouter)]            |
// |[source]| ===> | -> [data-pipe-1] ---------->--------->-\
//                 |    - [processor-1]                 |    \
//                 | -> [data-pipe-2 (ASampleProcessor)]-->---\
//                 V    - [*this-processor*]            |      \
//                 | -> [data-pipe-34] ---------->--------->----->===> |[sink]| 
//                 |    - [processor-3]                 |      /
//                 |    - [processor-4]                 |     /
//                 | -> [data-pipe-5 (Passthrough)]------->--/
//                 V    - [processor-5]                 |
//                 ------------>----------------->-------
//
// Data processing logic:
// - each data event object enters through [source], and leaves via [sink] or
//   if the data object receives a "drop" status due to a processor or
//   if the data object receives a non "pass" status at the final processor
//     (this is usually due to bad coding)
//   if a data object receives a "pass" status in a pipe without a sink
//     connection, the data object is effectively give a "drop" status
// 
// Possible data processing routes:
// 1) src => [pipe-1 -> processor-1 (pass)] => sink
// 2) src => [pipe-1 -> processor-1 (abort)] =>
//            [pipe-2 -> this-processor (pass)] => sink
// 3) src => [pipe-1 -> processor-1 (abort)] =>
//            [pipe-2 -> this-processor (abort)] => sink
//             [pipe-34 -> processor-3 (pass) -> processor-4 (pass)] => sink
// 4) src => [pipe-1 -> processor-1 (abort)] =>
//            [pipe-2 -> this-processor (abort)] => sink
//             [pipe-34 -> processor-3 (abort)] =>
//              [pipe-5 -> processor-5 (pass)] => sink
// 5) src => [pipe-1 -> processor-1 (abort)] =>
//            [pipe-2 -> this-processor (drop)] *

// From Fluency Platform ...
// - data from "Source" is presented either as a "doc" object
// - or as an un-named object with (obj, size, source) fields destructured

// Example data:
// {
//  "@message": "some-pattern=start date=2023-07-17 time=11:13:00 devname=\"ABCD-ROUTER\" devid=\"dev13579\" dstcountry=\"United States\"",
//  "@facility": "local7",
//  "@tags": ['example-tag']
// }

// Anatomy of a Processor:

// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {
    // Event selection criteria
    // - The first section of the code typically "selects" the event to be
    //   processed. Unless given a status of "abort", events will continue
    //   through the router to be processed again by the next processor down.
    //
    // - In other words, this sections peforms initial filtering of the input 
    //   (event record), and determines if the input should 
    //    A) proceed through this parser (Pipe), or 
    //    B) exit this parser, and be sent to the next Pipe, or Sink or 
    //    C) be "dropped" and removed from processing completely.

    // - Therefore, it is good practice to include selection criteria at the
    //   beginning of a processor, to only process the events that we intend to
    //   and to ingnore ("abort") all other events to be examined by processors
    //   further down the chain.

    // Most events have a "@message" field
    // - this field often contains the text to be 'parsed'
    let msg = obj["@message"]
    if (!msg){
        // Valid status values: "pass", "drop", "abort", "error"
        return {"status":"abort"}
    }

    // Example: Check the message for a pattern match
    if (!startsWith(msg, "some-pattern")){
        return {"status":"abort"}
    }

    // Many events also have a "@tag" field
    let tags = obj["@tags"]
    if (!tags) {
        return {"status":"abort"}
    }

    // Example: In this case, we look for specific start values in both the message, and the tag fields 
    if (startsWith(msg, "some-pattern=") && tags.Some( (_, tag) => startsWith(tag, "example" ))){
        // OK
    } else {
       return {"status":"abort"}
    }

    // Output fields settings
    // - Certain fields are expected in the output to Fluecy Platfom
    // - Other fields are nice to have, with values determined by convention

    // This field is Required
    obj["@type"] = "event"

    // These fields are nice to have by convention
    obj["@parser"] = "fpl-ASampleProcess" // This field records the parser used (this one), helps with idenfication of the processing path
    obj["@parserVersion"] = "20240611-1" // This field records the version/changes (YYYYMMDD-revision#)
    obj["@eventType"]="ProductName" // This field is for the descriptive product / event type, used for presentation in reports
    obj["@event_type"]="system_productName" // The event type. This is a special field. Must match the @productname object

    // Event parsing
    // The end goal of this section is typically, to convert the @message string into a JSON object (f).
    let m = mergeTagWithMessage(obj) // helper function

    // FPL may already have built-in functions for parsing
    let f = decoder_MixedKeyValue(m)
    //let f = decoder_CEF(m)
    //let f = decoder_QuotedKeyValue(m)

    // Assign the result of the parse (f) to obj
    // The field name here (added after parsing) must match the system_productName "@event_type" above)
    obj["@system_productName"] = f

    // Set tags (optional, depending on product)
    tags = ["product-name"]
    obj["@tags"] = tags

    // Discard original message (optional, if confident in parse)
    obj["@message"] = ""

    // Collect device metrics
    recordDeviceMetrics(obj, size)

    // Metaflow, data normalization (for network devices only)
    generateFusionEventWithCache(obj)

    // Return a status value
    return {"status":"pass"}
}

function generateFusionEventWithCache(obj) {
    let f = obj["@fortigate"]

    if (!(f.srcip && f.dstip && f.srcport && f.dstport && f.proto)) {
        // printf("invalid event record for flow: %v", f)
        return
    }

    let ts = obj["@timestamp"]

    // if (f.logid == "0000000020"){}
    // https://community.fortinet.com/t5/FortiGate/Technical-Tip-Notes-on-Traffic-log-generation-and-logging/ta-p/189711
    // https://docs.fortinet.com/document/fortianalyzer/7.4.1/administration-guide/750342/long-lived-session-handling

    let envelop = {
        partition: "default",
        dataType: "event",
        time_ms: ts
    }

    let sp = (f.srcport ? parseInt(f.srcport) : 0)
    let dp = (f.dstport ? parseInt(f.dstport) : 0)
    let prot = (f.proto ? parseInt(f.proto) : 0)

    let dur_E = (f.duration ? parseInt(f.duration) : 0)
    let sentP_E = (f.sentpkt ? parseInt(f.sentpkt) : 0)
    let rcvdP_E = (f.rcvdpkt ? parseInt(f.rcvdpkt) : 0)
    let sentB_E = (f.sentbyte ? parseInt(f.sentbyte) : 0)
    let rcvdB_E = (f.rcvdbyte ? parseInt(f.rcvdbyte) : 0)

    let dur = dur_E // default case
    let sentP = sentP_E
    let rcvdP = rcvdP_E
    let sentB = sentB_E
    let rcvdB = rcvdB_E

    // cache logic only when 'delta' fields exist
    if (f.sentdelta && f.devid) {
        let devid = f.devid

        let cacheName = sprintf("fg-session-%s", devid)
        let flag = Platform_Cache_Check(cacheName)
        if (!flag) {
            let ok = Platform_Cache_Register(cacheName, {expire: 600})
        }

        let key = f.sessionid
        // https://community.fortinet.com/t5/FortiGate/Technical-Tip-Multiple-sessions-are-assigned-with-same-session/ta-p/196925
        if (f.proto == "6" || f.proto == "17") {
            key = sprintf("%s_%s_%s_%s_%s_%s",f.sessionid, f.dstip, f.dstport, f.srcip, f.srcport, f.proto)
        }
        let record = Platform_Cache_Get(cacheName, key)

        if (record) {
            let {duration, sentpkt, rcvdpkt, sentbyte, rcvdbyte} = record
            if (dur_E - duration < 0) {
                // debug
                obj["@debug"] = sprintf("session out of order: %s" + key)
            }
            dur = dur_E - duration > 0 ? dur_E - duration : 0
            sentP = sentP_E - sentpkt > 0 ? sentP_E - sentpkt : 0
            rcvdP = rcvdP_E - rcvdpkt > 0 ? rcvdP_E - rcvdpkt : 0
            sentB = sentB_E - sentbyte > 0 ? sentB_E - sentbyte : 0
            rcvdB = rcvdB_E - rcvdbyte > 0 ? rcvdB_E - rcvdbyte : 0
        }

        // update cache
        Platform_Cache_Set(cacheName, key, {
            duration: dur_E,
            sentpkt: sentP_E,
            rcvdpkt: rcvdP_E,
            sentbyte: sentB_E,
            rcvdbyte: rcvdB_E,
        })
        // use sentdelta/rcvddelta, if possible
        // let sentB = (f.sentdelta ? parseInt(f.sentdelta) : (f.sentbyte ? parseInt(f.sentbyte) : 0))
        // let rcvdB = (f.rcvddelta ? parseInt(f.rcvddelta) : (f.rcvdbyte ? parseInt(f.rcvdbyte) : 0))
    }

    let source={
        flow: {
            sip: f.srcip,
            dip: f.dstip,
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
        dtype:"fortigate"
    }
    obj["@metaflow"] = source
    //printf("%v",source)
    Fluency_FusionEvent(envelop, source)
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
    let f = obj["@fortigate"]

    let deviceName = (f.devname ? f.devname : "unknown")

    let deviceEntry = Fluency_Device_LookupName(deviceName)
    if (!deviceEntry) {
        deviceEntry = {
            name:deviceName,
            ips: [sender],
            group:"FPL-detect: FortiGate NGFW",
            device: {
                name:"FortiGate NGFW",
                category:"Firewall"
            }
        }
        Fluency_Device_Add(deviceEntry)
    }
    let dimensions = {
        namespace:"fluency",
        app:"import",
        eventType:"FortiGateNGFW",
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

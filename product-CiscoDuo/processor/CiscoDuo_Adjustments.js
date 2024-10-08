// Description:
// Default Cisco Duo (Duo Security) Admin API integration event adjustments

// Data input format: ({ obj, size }) or ( doc )
function main({obj, size}) {
    //
    if(!obj["@timestamp"]){
        let t = new Time()
        obj["@timestamp"] = t.UnixMilli()
    }
    obj["@type"] = "event"
    
    // obj["@event_type"] = "duoAuthLog" // "duoTelephonyLog" // "duoAdminLog"
    let et = obj["@event_type"]
    if(et == "duoAuthLog") {
        obj["@source"] = "DuoAuthLog"
    } elseif (et == "duoTelephonyLog") {
        obj["@source"] = "DuoTelephonyLog"
    } elseif (et == "duoAdminLog") {
        obj["@source"] = "DuoAdminLog"
    } else {
        obj["@source"] = "duo"
    }
    obj["@eventType"] = "DuoSecurity"
    obj["@sender"] = "duo"
    obj["@parser"] = "fpl-CiscoDuoAdjustments"
    obj["@parserVersion"] = "20240925-2"
    return {"status":"pass"}
}

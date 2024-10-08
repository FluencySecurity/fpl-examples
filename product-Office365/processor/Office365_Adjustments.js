// Description:
// Default Office365 integration event adjustments
//  - Performs GeoIP lookup for clientIP field
//  - Adjustment for Data field (JSON format)
//  - Performs adjustment for lookup for ExtendedProperties field

// Data input format: ({ obj, size }) or ( doc )
function main({obj, size}) {
    //
    if(!obj["@timestamp"]){
        let t = new Time()
        obj["@timestamp"] = t.UnixMilli()
    }
    obj["@type"] = "event"
    obj["@sender"] = "office365"
    obj["@parser"] = "fpl-Office365Adjustments"
    obj["@parserVersion"] = "20240919-2"
    
    let f = obj["@fields"]
    if(!f){
        return { status: "error" }
    }
    
    // GeoIP lookup w/ ClientIP (ClientIPAddress)
    let cip = f.ClientIP
    if (!cip) {
        cip = f.ClientIPAddress
    }
    if (cip) {
        // Case where ClientIP = [<IP>]:<Port>
        let open = indexOf(cip, "[")
        let closed = indexOf(cip, "]")
        if (open >= 0 && closed >= 0){
            f.ClientIPOriginal = cip
            cip = subString(cip, open+1, closed)
            f.ClientIP = cip
        } else {
            // Case where ClientIP = <IP>:<Port>
            let k = indexOf(cip, ":")
            if(k > 0 && !isIPv6(cip)){
                f.ClientIPOriginal = cip
                cip = subString(cip, 0, k)
                f.ClientIP = cip
            }
        }
        try {
            let results = geoip(cip)
            if (len(results)){ // must have non-empty results
                f["_ip"]=results
            }
        } catch (e) {
            // Oh well, whatever...
        }
    }
    
    // Adjust AdditionalData
    // add 'AdditionalDataFields' object to office365 event
    let ad = f.AdditionalData
    if (ad && len(ad) > 0) {
        let ad_fields = {}
        for i, m = range ad {
            if (m) {
                if(m.Name && m.Value){
                    let key = replaceAll(m.Name, '\\.', '_', -1)
                    ad_fields[key]=m.Value
                }
            }
        }
        if(len(ad_fields)) {
            f.AdditionalDataFields=ad_fields
        }
    }

    // Adjust DeviceProperties
    // add 'DevicePropertiesFields' object to office365 event
    let dp = f.DeviceProperties
    if (dp && len(dp) > 0) {
        let dp_fields = {}
        for i, m = range dp {
            if (m) {
                if(m.Name && m.Value){
                    let key = replaceAll(m.Name, '\\.', '_', -1)
                    dp_fields[key]=m.Value
                }
            }
        }
        if(len(dp_fields)) {
            f.DevicePropertiesFields=dp_fields
        }
    }

    // Adjust Parameters
    // add 'ParametersFields' object to office365 event
    let po = f.Parameters
    if (po && typeof(po) == "list" && len(po) > 0) {
        let po_fields = {}
        for i, m = range po {
            if (m) {
                if(m.Name && m.Value){
                    let key = replaceAll(m.Name, '\\.', '_', -1)
                    po_fields[key]=m.Value
                }
            }
        }
        if(len(po_fields)) {
            f.ParametersFields=po_fields
        }
    }

    // Adjust ExtendedProperties
    // add 'ExtendedPropertiesFields' object to office365 event
    let ep = f.ExtendedProperties
    if (ep && len(ep) > 0) {
        let ep_fields = {}
        for i, m = range ep {
            if (m) {
                if(m.Name && m.Value){
                    let key = replaceAll(m.Name, '\\.', '_', -1)
                    ep_fields[key]=m.Value
                    
                    if(key=="additionalDetails"){
                        // Adjustment for nested additionalDetails field (JSON format)
                        // add 'additionalDetailsFields' object to office365 event
                        let data = m.Value
                        // check to see if additionalDetails exists
                        if (data && data != "{}"){
                            try {
                                let adf = parseJson(data)
                                ep_fields["additionalDetailsFields"]=adf
                                //print(JSON.stringify(obj));
                            } catch (e) {
                                // Oh well, whatever...
                            }
                        }
                    }
                }
            }
        }
        if(len(ep_fields)) {
            f.ExtendedPropertiesFields=ep_fields
        }
    }
    
    // Adjust ModifiedProperties
    // add 'ModifiedPropertiesFields New/Old' object to office365 event
    let mp = f.ModifiedProperties
    if (mp && len(mp) > 0) {
        let mp_fields_old = {}
        let mp_fields_new = {}
        for i, m = range mp {
            if (m && typeof(m) == "jsonObj") {
                if(m.Name && (m.OldValue || m.OldValue == "")){
                    let oldkey = replaceAll(m.Name, " ", "", -1)
                    oldkey = replaceAll(oldkey, '\\.', '_', -1)
                    mp_fields_old[oldkey]=m.OldValue
                }
                if(m.Name && (m.NewValue || m.NewValue == "")){
                    let newkey = replaceAll(m.Name, " ", "", -1)
                    newkey = replaceAll(m.Name, '\\.', '_', -1)
                    mp_fields_new[newkey]=m.NewValue
                }
            }
        }
        if(len(mp_fields_old)) {
            f.ModifiedPropertiesFieldsOld=mp_fields_old
        }
        if(len(mp_fields_new)) {
            f.ModifiedPropertiesFieldsNew=mp_fields_new
        }
    }
    
    // Adjustment for Data field (JSON format)
    // add 'DataFields' object to office365 event
    let data = f.Data
    if (data && data != "{}" && data != ""){
        if (len(data) > 2048) {
            f.DataFields = {"error":"Data string length exceeds 2048 chars"}
        } else {
            let ops = f.Operation
            if (ops == "AlertTriggered" || ops == "AlertEntityGenerated" || ops == "AirInvestigationData"){
                try {
                    let df = parseJson(data)
                    f.DataFields=df
                    //print(JSON.stringify(obj));
                } catch (e) {
                    // Oh well, whatever...
                }
            }
        }
    }
    // Update @fields
    obj["@fields"] = f
    return { status: "pass" }
}

// Description:
// Default AzureAudit integration event adjustments

// Data input format: ({ obj, size }) or ( doc )
function main({obj, size}) {
    //
    if(!obj["@timestamp"]){
        let t = new Time()
        obj["@timestamp"] = t.UnixMilli()
    }
    obj["@type"] = "event"
    obj["@sender"] = "azureAudit"
    obj["@parser"] = "fpl-AzureAuditAdjustments"
    obj["@parserVersion"] = "20240430-1"
    
    let et = obj["@event_type"] 
    if(et == "@azureDirectoryAudit"){
        // azureDirectoryAudit events
        obj["@source"] = "AzureDirectoryAudit"
        obj["@eventType"] = "AzureDirectoryAudit"
    } elseif (et == "@azureSignIn") {
        // azureSignIn events
        obj["@source"] = "AzureSignIn"
        obj["@eventType"] = "AzureSignIn"
    } elseif (et == "@azureProvisioning") {
        // azureProvisioning events
        obj["@source"] = "AzureProvisioning"
        obj["@eventType"] = "AzureProvisioning"
    } else {
        return { status: "error" }
    }

    return { status: "pass" }
}

// Description:
// Default Azure EventHubs integration event adjustments

// Data input format: ({ obj, size }) or ( doc )
function main({obj, size}) {
    //
    if(!obj["@timestamp"]){
        let azure = obj["@azure"]
        let category = azure.category
        let timeField = azure.time
        if !timeField {
            return {"status":"error"}
        }
        // https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-network-azurefirewalls-logs
        if (category == "AzureFirewallApplicationRule" || category == "AzureFirewallNetworkRule" || category == "AzureFirewallDnsProxy"){
            // drop 'legacy' category types
            return {"status":"drop"}
        }
        if (startsWith(category, "AZFW")){
            let t = new Time("2006-01-02T15:04:05.999999+00:00" , timeField)
            obj["@timestamp"] = t.UnixMilli() 
        } else {
            let t = new Time("2006-01-02T15:04:05.999999999Z" , timeField)
            obj["@timestamp"] = t.UnixMilli() 
        }
    }
    obj["@type"] = "event"
    
    obj["@event_type"] = "azure"
    obj["@eventType"] = "AzureEventHubs"
    obj["@sender"] = "azure"
    obj["@source"] = "eventhubs"
    obj["@parser"] = "fpl-AzureEventHubsAdjustments"
    obj["@parserVersion"] = "20240920-6"
    return {"status":"pass"}
}

// Description:
// Default CrowdStrike Falcon Event Stream API adjustments

// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {
    if(!obj["@timestamp"]){
        let t = new Time()
        obj["@timestamp"] = t.UnixMilli()
    }

    obj["@type"] = "event"
    obj["@parser"] = "fpl-CrowdStrikeFalconEvent"
    obj["@parserVersion"] = "20240730-1"
    obj["@eventType"] = "CSFalcon"
    obj["@sender"] = "falcon"
    obj["@source"] = "falcon"
    if(obj["@event_type"] == "@falcon"){
        obj["@event_type"] = "falcon"
    }

    let envelop = obj["@falcon"]
    if (envelop) {
        let eventType = envelop.eventType
        // printf("%s",eventType)
        if eventType == "IncidentSummaryEvent" {
            let incidentID = envelop.event.IncidentID
            // printf("%s",incidentID)
            // source "Falcon:default"
            let {integration, account} = regexp("(?P<integration>.*):(?P<account>.*)", source)
            printf("account: %s",account)
            // let segments = split(source, ":")
            // printf("account: %s",segments[1])
            let {incident} = Platform_PluginLambda("Falcon", account, () => {
                let incident = Plugin_Falcon_GetIncident(incidentID)
                if incident {
                    // envelop.incident = incident
                    // printf("%s", incident)
                    return {incident}
                } else {
                    printf("unknown incidentID: %s", incidentID)
                    return {}
                }
            })
            if incident {
                envelop.incident = incident
            }
       }
    }

    return {"status":"pass"}
}

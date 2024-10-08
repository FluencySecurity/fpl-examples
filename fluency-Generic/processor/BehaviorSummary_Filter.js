// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {
    //
    
    // setup cache
    let id = "default"
    let cacheName = sprintf("behavior-summary-filter-%s", id)
    let flag = Platform_Cache_Check(cacheName)
    if (!flag) {
        let ok = Platform_Cache_Register(cacheName, {expire: 86400})
    }
        
    let key = obj.id
    let summary = obj.summary
    
    let cached = Platform_Cache_Get(cacheName, key)
    if (cached) {
        printf("cache hit for %s", key)
        // printf("%v", cached)
    }
    let notified = notificationCriterion(cached, summary)
    if (notified) {
        cached = {
            riskScore: summary.riskScore,
            updatedOn: summary.updatedOn,
            
        }
        Platform_Cache_Set(cacheName, key, cached)
        return {"status":"abort"} // send to other pipe, for further processing
    } else {
        //return {"status":"drop"} 
        return {"status":"drop"} // ignored, (drop or pass)
    }
    return {"status":"error"} // placeholder return statement
}

function notificationCriterion(cached, summary) {
    let threshold = 3000
    if(cached){
        if (summary.riskScore >= (cached.riskScore * 2)){
            printf("update event, score more than doubled: %d -> %d", cached.riskScore, summary.riskScore)
            return true
        } else {
            printf("update event, score change minimal")
            return false
        }
    } else {
        if (summary.riskScore >= threshold){
            printf("new event, high risk: %d", summary.riskScore)
            return true
        } else {
            // printf("new event, low risk: %d", summary.riskScore)
            return false
        }
    }
    return false
}

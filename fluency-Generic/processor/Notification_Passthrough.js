// Description:
// Default notification event passthrough

// Data input format: ({ obj, size }) or ( doc )
function main({obj, size}) {
    //
    let siteInfo = Platform_Site_GetInfo()
    //printf("%v",siteInfo)
    obj.account = siteInfo.account
    obj.siteURL = siteInfo.siteURL
    return {"status":"pass"} 
}

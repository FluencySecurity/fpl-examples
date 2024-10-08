// Data input format: ({ obj, size, source }) or ( doc )
function main({obj, size, source}) {
    //
    let emailEndpoint = "BehaviorSummary_Export"
    let key = obj.id
    let summary = obj.summary

    let doc = buildEmail(obj)
    Platform_Action_Endpoint(emailEndpoint, doc)
        
    return { status: "abort" }
}

function buildEmail(event) {    
    let template = `
{{define "ruleAttribute"}}
<li>
{{ if eq (len .values) 1 }}
<p>{{.aliase}}: <b>{{ index .values 0 }}</b></p>
{{ else }}
<p>{{.aliase}}:</p>
<ul>{{range .values}}<li><pre>{{ . }}</pre></li>{{end}}</ul>
{{ end }}
</li>
{{end}}
{{define "hitRisk"}}
<li><p><b>{{ . }}</b></p></li>
{{end}}
{{define "ruleSummaryHit"}}
<ul>{{range .risks}}{{ template "hitRisk" . }}{{end}}</ul>
{{end}}
{{define "ruleSummary"}}
<li>
<p><b>{{.behaviorRule}}</b> ({{ .behavior }}) -  Score: {{.riskScore}}; Event(s): {{ .count }}</p>
{{ if .hits }}
<p>Hits:</p>
<ul>{{range .hits}}{{ template "ruleSummaryHit" . }}{{end}}</ul>
{{ end }}
{{ if .attributeSummaries }}
<p>Attribute Fields:</p>
<ul>{{range .attributeSummaries}}{{ template "ruleAttribute" . }}{{end}}</ul>
{{ end }}
</li>
{{end}}
{{define "comment"}}
<li>
<p><b>User</b>: {{.username}}</p>
{{ if .actions }}
<p><b>Action</b>: {{ index .actions 0 }}</p>
{{end}}
{{ if .content }}
<p><b>Comments</b>: - <pre>{{ .content }}</pre></p>
{{end}}
</li>
{{end}}
<p>Time: {{ .bsTime }}</p>
<p>Entity / Key ({{.keyType}}): <b>{{.key}}</b></p>
<p>RiskScore: <b>{{.riskScore}}</b></p>
<p>Behavior Rules:</p>
<ul>{{range .summaryList}}{{ template "ruleSummary" . }}{{end}}</ul>
{{ if .comments }}
<p>History / Comments:</p>
<ul>{{range .comments}}{{ template "comment" . }}{{end}}</ul>
{{end}}
<p><a href="{{ .summaryURL }}">Review Behavior Summary on Fluency</a></p>
`
    let subjectTemplate = `Behavior Incident Summary ({{.status}}): {{.summary.key}} - {{.summary.keyType}}: {{.summary.riskScore}}`
    
    let siteInfo = Platform_Site_GetInfo()
    //printf("%v",siteInfo)
    let subject = template(subjectTemplate, event)
    let s = jsonClone(event.summary)
    
    if (siteInfo) {
        subject = sprintf("[%s] %s", siteInfo.account, subject)
        s.summaryURL = buildSummaryURL(siteInfo.siteURL, event.id)
        let t = new Time(event.summary.to)
        s.bsTime = t.Format("2006-01-02T15:04:05-07:00")
    }
    
    let html = htmlTemplate(template, s)
    
    let m = {
        subject : subject,
        html: html
    }
    //printf("%v",html)
    //printf("%v",subject)
    return m
}

function buildSummaryURL(siteURL, key) {
    return sprintf("%s/analytics/BehaviorSummary?q=id:%s", siteURL, key)
}



// Template: Generic HTML Email (notification) Action
// Input: event: { subject, html }
//        config: { *values from Endpoints UI* }

function main( {event, config={}} ) {
    let options = {
        to: config.to,
        cc: config.cc,
        subject: event.subject,
        html: event.html
    }
    Platform_Notification_Email(options)
    return { status: "pass" }
}
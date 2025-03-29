# mod_secure_message

Email link to recipient, read and reply on server.

Messages can be stored via the API. An email with a link will be sent to the recipient.

The recipient can read the message at the link location and reply or delete the message.
A reply will be delivered to the message sender site.

All messages are automatically deleted after a week or if the recipient deleted the message.

## API

*TO BE DOCUMENTED*

## Configuration

The communication is secured using OAuth.

To let a site send messages, you need to add an OAuth key with access permissions to `secure_message/*`

Optionally there is a default site for delivering messages using the reply form.

It uses the following configuration keys:

 * `mod_secure_message.event_url` The API endpoint for contact form messages (and other events).
 * `mod_secure_message.event_oauth_key` The consumer key for signing the messages
 * `mod_secure_message.event_oauth_secret` The consumer secret for signing the messages

Besides these there are the following keys:

 * `mod_secure_message.sign_key_secret` The secret to sign the emailed links to messages
 * `mod_secure_message.log_cleanup` Set to `1` to enable weekly truncation of the db stored log tables


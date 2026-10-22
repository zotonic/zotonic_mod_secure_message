# zotonic_mod_secure_message

Store a message on the site and email the recipient a signed link to read it.
The message body is not included in the notification email. Recipients can reply
through the site or delete the message. Replies and status events are posted to
the sender's service as JSON.

## Setup

Enable `mod_secure_message` on a database-backed Zotonic site with outgoing email
configured. Installation creates the `secure_message` and `secure_message_event`
tables. The supplied templates use the site's `base.tpl`, `email_base.tpl`, wires
and localization templates. Override `email_secure_message.tpl` to customize the
notification email.

The module supplies two HTTPS page dispatch rules:

- `secure_message_view`: `/secure/msg/<key>/<signature>` to read a message.
- `secure_message_form`: `/secure/msg` to send a new contact-form message.

Set `mod_secure_message.event_url` if the standalone form should deliver messages
to a default service. A message-specific `reply_url` enables the reply form on
that message's page.

## Relay API

Send a JSON POST to `/api/model/secure_message/post/relay`. Authenticate using the
site's standard API authentication. The calling identity must have `use`
permission for `mod_secure_message` as well as the required API topic access.

For a site configured with bearer-token authentication:

```sh
curl --request POST \
  --url 'https://messages.example.com/api/model/secure_message/post/relay' \
  --header "Authorization: Bearer $TOKEN" \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --data '{
    "recipient": "reader@example.com",
    "sender": "Support",
    "subject": "Your answer",
    "message": "<p>Here is your answer.</p>",
    "message_id": "case-123",
    "reply_url": "https://sender.example.com/message-events",
    "language": "en"
  }'
```

| Field | Required | Meaning |
| --- | --- | --- |
| `recipient` | Yes | Email address receiving the link. |
| `sender` | Yes | Sender text displayed on the message page. |
| `subject` | Yes | Subject displayed on the message page. |
| `message` | Yes | Message HTML, sanitized before storage. |
| `message_id` | No | Sender's identifier, returned in the result and included in callbacks. Defaults to the generated message key. |
| `reply_url` | No | JSON callback destination for all message events. Also enables the reply form. |
| `status_url` | No | Stored for compatibility, but not used for callback routing. |
| `language` | No | Message language; invalid or omitted values use the context language. |

The model returns `{ok, #{<<"status">> => <<"ok">>, <<"result">> =>
#{<<"message_id">> => Id}}}` on successful insertion. The HTTP API serializes
this result through its standard response handling. Permission denial returns
`eacces`. Missing required fields are not handled by a structured validation layer.

A successful relay response confirms storage, not successful email delivery.
If sending the notification fails, the stored message is marked `is_sent_error`;
insertion still returns success.

For trusted Erlang callers, `m_secure_message:insert(Props, Context)` accepts an
atom-keyed property list. It returns `{ok, GeneratedKey}`, where the key is a
binary, not the numeric database ID. Direct insertion does not check the relay
API permission. See the `m_secure_message` module documentation for lookup,
resend, deletion and callback functions.

## Callbacks and replies

Message events use `reply_url`. If it is undefined, delivery falls back to
`mod_secure_message.event_url`. `status_url` is not used. Callbacks are JSON POSTs
queued after one second; failed HTTP requests retry after 1800 seconds. A missing
default URL produces an error instead of delivering the event.

| Event | Additional fields and behavior |
| --- | --- |
| `read` | Queued on successful page lookup. |
| `reply` | Includes `subject` (prefixed with `Re: ` if needed), `message` and `language`. |
| `sent` | Includes `is_final` from the email notification. |
| `failed` | Includes `status` and `is_final`; sender-disabled failures are ignored. |
| `bounced` | Sent for a known outgoing message with a recipient and message ID. |

All message events include `message_id` and `recipient`. The standalone form
sends a `message` event to the default URL with `message`, `email`, `name_first`,
`address_country`, `address_state` and `language`. Form success indicates queuing,
not receipt by the external service. “Send & Delete Message” queues the reply
before deleting the original message.

Callbacks use `z_fetch` with a context logged in as user 1. Configure destination
authentication through Zotonic's URL-fetch integration. For example, `mod_oauth2`
can attach a bearer token associated with user 1 and the destination HTTPS host.
The old `event_oauth_key` and `event_oauth_secret` settings are not read by this
module; it does not itself sign callbacks with OAuth 1.

## Configuration

These are per-site `m_config` settings:

| Key | Behavior |
| --- | --- |
| `mod_secure_message.event_url` | Default callback URL for contact-form messages and events without a `reply_url`. |
| `mod_secure_message.sign_key_secret` | Site secret for signed links. Generated and saved on first use if empty. Changing it invalidates existing links. |
| `mod_secure_message.log_cleanup` | Disabled by default. When true, hourly cleanup also deletes records older than seven days from the site's `log` and `log_email` tables, including records unrelated to this module. |

## Expiry, access and storage

Messages expire seven days after insertion. Reading does not extend that period.
Expired messages immediately become unavailable through their links; hourly
cleanup removes the database rows. Recipient deletion removes the message
immediately. Associated `secure_message_event` rows are deleted by cascade.

Anyone holding the complete signed link can read, reply to or delete the message
without logging in. Keep these links private. Successful page lookup records the
viewer's IP address and user agent, updates the first-open time and queues a read
event.

Message data is serialized as an Erlang term in a database bytea column. Encryption
at rest is not implemented by this module. Deletion removes live message/event
rows; it does not erase database backups, callback copies at the receiving service
or unrelated logs.

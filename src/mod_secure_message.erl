%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2017-2025 Marc Worrell
%% @doc Implement autodestruct messages, relayed from another service.
%% @end

%% Copyright 2017-2025 Marc Worrell
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% 
%%     http://www.apache.org/licenses/LICENSE-2.0
%% 
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(mod_secure_message).
-moduledoc(#{
    zotonic_keywords => [
        "reference", "site_administrator", "integrator", "module",
        "email", "api_and_integration", "configuration", "privacy"
    ]
}).
-moduledoc("
Store short-lived messages on the site and email recipients a signed link
instead of the message body. Recipients can read, reply to and delete a
message without logging in. Replies and delivery/read events are sent to
an external service as JSON.

## Setup and configuration

Enable `mod_secure_message` on a database-backed site with outgoing email
configured. Schema installation creates `secure_message` and
`secure_message_event`. The supplied pages use the site's `base.tpl`,
`email_base.tpl`, Zotonic wires and localization templates. Customize
`email_secure_message.tpl` for the site's notification text.

Senders use the `m_secure_message` relay API and need `use` permission for
`mod_secure_message`. HTTP access uses Zotonic's standard model API and its
configured authentication. Recipient access instead requires the complete
signed link. Both page dispatch rules request HTTPS:

- `secure_message_view`: `/secure/msg/<key>/<signature>`.
- `secure_message_form`: `/secure/msg`, a form for a new contact message.

Per-site configuration values are:

| Key under `mod_secure_message` | Purpose |
| --- | --- |
| `event_url` | Default JSON callback URL for contact-form messages and events without a message-specific `reply_url`. |
| `sign_key_secret` | Site secret used to sign links; generated and saved on first use if empty. Changing it invalidates existing links. |
| `log_cleanup` | If true, hourly cleanup also deletes rows older than seven days from the site's `log` and `log_email` tables. Defaults to disabled. |

Callbacks use `z_fetch` in the context of user 1. Configure any destination
credentials through Zotonic's URL-fetch authentication integration. This
module does not read the legacy `event_oauth_key` or `event_oauth_secret`
settings and does not itself sign outgoing requests with OAuth 1.

## Message lifetime and events

Messages expire seven days after insertion. Expired links stop working at
expiry; the hourly `tick_1h` observer removes expired database rows. Reading
does not extend the expiry. Recipient deletion removes the row immediately;
associated message-event rows are deleted by the database's cascading
foreign key.

Reading logs the peer address and user agent, records the first-open time,
and queues a `read` event. Email notifications produce `sent`, `failed` and
`bounced` callbacks for known outgoing messages; `sender_disabled` failures
are ignored. Replies queue a `reply` event, optionally followed by deletion.
The page shows a reply form only when the message has a `reply_url`.

Callbacks are queued for delivery after one second. Failed HTTP requests
are rescheduled after 1800 seconds. The form's success display means the
event was queued, not that the receiving service accepted it.

## Storage and link access

The message HTML is sanitized before storage. Payloads are serialized Erlang
terms in a database bytea column; encryption is not implemented. Possession
of the signed link permits reading, replying and deletion until expiry.
Deletion covers the live message and its event rows, not database backups,
external callback copies or unrelated logs.
").

-mod_author("Marc Worrell <marc@worrell.nl>").
-mod_title("Secure email message reading").
-mod_description("Implement autodestructing emails").
-mod_schema(2).

-export([
    observe_tick_1h/2,
    event/2,

    observe_email_sent/2,
    observe_email_failed/2,
    observe_email_bounced/2,

    manage_schema/2
    ]).

-include_lib("zotonic_core/include/zotonic.hrl").

observe_tick_1h(tick_1h, Context) ->
    m_secure_message:periodic_destruct(Context).

event(#postback{message={secure_delete, Args}}, Context) ->
    {key, Key} = proplists:lookup(key, Args),
    {signature, Signature} = proplists:lookup(signature, Args),
    case m_secure_message:delete(Key, Signature, Context) of
        ok ->
            z_render:wire({redirect, [{dispatch, secure_message_form},{deleted,1}]}, Context);
        {error, _} ->
            z_render:wire({alert, [{text, ?__("Sorry, could not delete the message", Context)}]}, Context)
    end;
event(#submit{message={secure_reply, Args}, form=FormId}, Context) ->
    {key, Key} = proplists:lookup(key, Args),
    case Key of
        undefined ->
            % New message to our preferred handler
            Reply = z_context:get_q_validated(<<"reply">>, Context),
            Email = z_context:get_q_validated(<<"email">>, Context),
            NameFirst = z_context:get_q_validated(<<"name_first">>, Context),
            Country = z_context:get_q_validated(<<"address_country">>, Context),
            State = z_context:get_q(<<"address_state">>, Context),
            Msg = #{
                <<"event">> => <<"message">>,
                <<"message">> => Reply,
                <<"email">> => Email,
                <<"name_first">> => NameFirst,
                <<"address_country">> => Country,
                <<"address_state">> => State,
                <<"language">> => z_context:language(Context)
            },
            _ = m_secure_message:send_generic_event(Msg, Context),
            z_render:wire([
                    {remove, [{target,FormId}]},
                    {show, [{target, "reply-sent"}]}
                ], Context);
        _ ->
            % Reply to existing message
            {signature, Signature} = proplists:lookup(signature, Args),
            SubmitButton = z_context:get_q(z_submitter, Context),
            Reply = z_context:get_q_validated(reply, Context),
            case m_secure_message:fetch_by_key(Key, Signature, Context) of
                {ok, Msg} ->
                    Subject0 = z_convert:to_binary(proplists:get_value(subject, Msg)),
                    Subject = case Subject0 of
                        <<"Re: ", _/binary>> -> Subject0;
                        _ -> <<"Re: ", Subject0/binary>>
                    end,
                    ReplyArgs = #{
                        <<"event">> => <<"reply">>,
                        <<"subject">> => Subject,
                        <<"message">> => Reply,
                        <<"language">> => proplists:get_value(language, Msg)
                    },
                    _ = m_secure_message:send_message_event(Msg, ReplyArgs, Context),
                    Context1 = z_render:wire([
                            {remove, [{target,FormId}]},
                            {show, [{target, "reply-sent"}]}
                        ], Context),
                    case z_convert:to_binary(SubmitButton) of
                        <<"msg-delete">> ->
                            % Delete message, remove it from the screen
                            m_secure_message:delete(proplists:get_value(id, Msg), Context),
                            z_render:wire({remove, [{target, "secure-message"}]}, Context1);
                        <<"msg">> ->
                            Context1
                    end;
                {error, _} ->
                    z_render:wire({alert, [
                            {text, ?__("Could not open this email. Please reload the page and retry.", Context)},
                            {action, {reload, []}},
                            {button, ?__("Reload", Context)}
                        ]}, Context)
            end
    end.

observe_email_sent(#email_sent{message_nr=MsgId, is_final=IsFinal}, Context) ->
    m_secure_message:send_message_event(
        MsgId,
        #{ <<"event">> => <<"sent">>, <<"is_final">> => IsFinal },
        Context).

observe_email_failed(#email_failed{reason=sender_disabled}, _Context) ->
    undefined;
observe_email_failed(#email_failed{message_nr=MsgId, is_final=IsFinal, status=Status}, Context) ->
    m_secure_message:send_message_event(
        MsgId,
        #{ <<"event">> => <<"failed">>, <<"status">> => Status, <<"is_final">> => IsFinal },
        Context).

%% @doc Mark an email address as bouncing, only marks for messages which we know we have sent.
observe_email_bounced(#email_bounced{recipient=undefined}, _Context) ->
    ok;
observe_email_bounced(#email_bounced{message_nr=undefined}, _Context) ->
    ok;
observe_email_bounced(#email_bounced{message_nr=MsgId}, Context) ->
    m_secure_message:send_message_event(MsgId, #{ <<"event">> => <<"bounced">> }, Context).


manage_schema(_Version, Context) ->
    m_secure_message:install(Context).


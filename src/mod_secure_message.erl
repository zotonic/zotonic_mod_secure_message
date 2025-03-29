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


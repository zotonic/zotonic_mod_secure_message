%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2017-2025 Marc Worrell
%% @doc Model functions for autodestruct messages
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

-module(m_secure_message).

-export([
    m_get/3,
    m_post/3,

    periodic_destruct/1,

    insert/2,
    delete/3,
    delete/2,

    fetch_by_key/3,

    get_url/2,
    send_link/2,

    is_valid_signature/4,
    sign/3,

    send_test_event/1,
    send_generic_event/2,
    send_message_event/3,
    task_send_message_event/3,

    install/1
    ]).

-include_lib("zotonic_core/include/zotonic.hrl").

m_get([ <<"qlookup">> | Rest ], _Msg, Context) ->
    case get_message_qarg(Context) of
        {ok, Msg} -> {ok, {Msg, Rest}};
        {error, _} -> {error, enoent}
    end;
m_get(_Path, _Msg, _Context) ->
    {error, enoent}.

m_post([ <<"relay">> ], #{ payload := Payload }, Context) ->
    case z_acl:is_allowed(use, mod_secure_message, Context) of
        true ->
            do_receive(Payload, Context);
        false ->
            {error, eacces}
    end.

do_receive(Payload, Context) ->
    #{
        <<"recipient">> := Recipient,
        <<"sender">> := Sender,
        <<"subject">> := Subject,
        <<"message">> := Message
    } = Payload,
    ReplyUrl = maps:get(<<"reply_url">>, Payload, undefined),
    StatusUrl = maps:get(<<"status_url">>, Payload, undefined),
    MessageId = maps:get(<<"message_id">>, Payload, undefined),
    Language = maps:get(<<"language">>, Payload, z_context:language(Context)),
    Language1 = case z_language:to_language_atom(Language) of
        {ok, Iso} -> Iso;
        {error, _} -> z_context:language(Context)
    end,
    Props = [
        {recipient, bin(Recipient)},
        {sender, bin(Sender)},
        {reply_url, bin(ReplyUrl)},
        {status_url, bin(StatusUrl)},
        {subject, bin(Subject)},
        {message, bin(Message)},
        {message_id, bin(MessageId)},
        {language, bin(Language1)}
    ],
    case m_secure_message:insert(Props, Context) of
        {ok, SentMessageId} ->
            ReturnMsgId = case MessageId of
                undefined -> SentMessageId;
                _ -> MessageId
            end,
            {ok, #{
                <<"status">> => <<"ok">>,
                <<"result">> => #{
                    <<"message_id">> => z_convert:to_binary(ReturnMsgId)
                }
            }};
        {error, Error} ->
            {error, Error}
    end.

bin(undefined) -> undefined;
bin(B) when is_binary(B) -> B;
bin(Other) -> z_convert:to_binary(Other).


%% @doc Delete all emails marked for destruction
-spec periodic_destruct(#context{}) -> ok.
periodic_destruct(Context) ->
    _ = z_db:q("delete from secure_message where destruct < now()", Context),
    case z_convert:to_bool(m_config:get_value(mod_secure_message, log_cleanup, Context)) of
        true ->
            _ = z_db:q("delete from log_email where created < $1", [prev_week()], Context),
            _ = z_db:q("delete from log where created < $1", [prev_week()], Context);
        false ->
            ok
    end,
    ok.

%% @doc Insert a new message
%% @todo Email link to recipient
-spec insert(list(), #context{}) -> {ok, integer()} | {error, term()}.
insert(Props, Context) ->
    {recipient, Recipient} = proplists:lookup(recipient, Props),
    {sender, Sender} = proplists:lookup(sender, Props),
    {subject, Subject} = proplists:lookup(subject, Props),
    {message, Message} = proplists:lookup(message, Props),
    Language = case proplists:get_value(language, Props) of
        undefined -> z_context:language(Context);
        <<>> -> z_context:language(Context);
        Lng -> Lng
    end,
    Data = [
        {reply_url, proplists:get_value(reply_url, Props)},
        {status_url, proplists:get_value(status_url, Props)},
        {subject, Subject},
        {message, z_sanitize:html(Message, Context)},
        {message_id, proplists:get_value(message_id, Props)},
        {recipient, Recipient},
        {sender, Sender}
    ],
    case encrypt_payload(Data, Props, Context) of
        {ok, {CryptoType, CrypoData, DataBin}} ->
            InsertProps = [
                {sent_message_id, <<>>},
                {generated_id, z_ids:id(30)},
                {sign_key, z_ids:id(50)},
                {destruct, next_week()},
                {language, Language},
                {crypto_type, CryptoType},
                {crypto_data, CrypoData},
                {data, DataBin}
            ],
            case z_db:insert(secure_message, InsertProps, Context) of
                {ok, Id} ->
                    send_link(Id, Data ++ InsertProps, Context),
                    {ok, proplists:get_value(generated_id, InsertProps)};
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

%% @doc Send the recipient an email with the link.
%%      Ensure that the link has the correct language
send_link(Id, Context) ->
    case fetch_decrypt(Id, Context) of
        {ok, Props} ->
            send_link(Id, Props, Context);
        {error, _} = Error ->
            Error
    end.

send_link(Id, Props, Context) ->
    {recipient, Recipient} = proplists:lookup(recipient, Props),
    {language, Language} = proplists:lookup(language, Props),
    ContextLang = case Language of
        <<>> -> Context;
        undefined -> Context;
        Lang ->
            case z_language:to_language_atom(Lang) of
                {ok, Iso} ->
                    mod_translation:set_language(Iso, Context);
                {error, _} -> Context
            end
    end,
    {ok, Url} = get_url(Id, ContextLang),
    Vars = [
        {recipient, Recipient},
        {url, Url}
    ],
    case z_email:send_render(Recipient, "email_secure_message.tpl", Vars, ContextLang) of
        {ok, EmailId} ->
            z_db:q("
                update secure_message
                set sent_message_id = $2
                where id = $1",
                [Id, EmailId],
                Context),
            maybe_log_db_event(Id, <<"sent">>, EmailId, undefined, undefined, Context),
            ok;
        {error, Error} ->
            ?LOG_ERROR(#{
                in => zotonic_mod_secure_message,
                text => <<"Error sending message">>,
                result => error,
                reason => Error,
                recipient => Recipient
            }),
            z_db:q("
                update secure_message
                set is_sent_error = true
                where id = $1",
                [Id],
                Context),
            maybe_log_db_event(Id, <<"sent-error">>, <<>>, undefined, undefined, Context),
            {error, Error}
    end.

%% @doc Delete a message using its generated_id and request signature.
-spec delete(Key, Signature, Context) -> ok | {error, term()} when
    Key :: binary(),
    Signature :: binary(),
    Context :: z:context().
delete(Key, Signature, Context) ->
    case fetch_by_key(Key, Signature, Context) of
        {ok, Msg} ->
            MsgId = proplists:get_value(id, Msg),
            z_db:q("
                delete from secure_message
                where id = $1",
                [MsgId],
                Context),
            ok;
        {error, _} = Error ->
            Error
    end.

%% @doc Delete a message using its message id
-spec delete(MsgId, Context) -> ok when
    MsgId :: integer(),
    Context :: z:context().
delete(MsgId, Context) ->
    z_db:q("
        delete from secure_message
        where id = $1",
        [MsgId],
        Context),
    ok.

-spec get_url(MsgId, Context) -> {ok, Url} | {error, term()} when
    MsgId :: integer(),
    Context :: z:context(),
    Url :: binary().
get_url(MsgId, Context) ->
    case z_db:q_row("
        select generated_id, sign_key
        from secure_message
        where id = $1
          and destruct > now()",
        [MsgId],
        Context)
    of
        undefined -> {error, notfound};
        {GeneratedId, SignKey} ->
            Signature = sign(GeneratedId, SignKey, Context),
            Url = z_dispatcher:url_for(
                        secure_message_view,
                        [ {key, GeneratedId}, {signature, Signature} ],
                        Context),
            {ok, z_context:abs_url(iolist_to_binary(Url), Context)}
    end.

%% @doc Find a message using the query arguments, this adds an event to the log
-spec get_message_qarg(Context) -> {ok, Msg} | {error, term()} when
    Context :: z:context(),
    Msg :: proplists:proplist().
get_message_qarg(Context) ->
    Key = z_context:get_q(key, Context),
    Signature = z_context:get_q(signature, Context),
    case fetch_by_key(Key, Signature, Context) of
        {error, _} = Error ->
            Error;
        {ok, Msg} ->
            update_view_dates(Msg, Context),
            MsgId = proplists:get_value(id, Msg),
            log_access(MsgId, Context),
            send_message_event(Msg, #{ <<"event">> => <<"read">> }, Context),
            Msg1 = [ {view_count, view_count(MsgId, Context)} | Msg ],
            {ok, Msg1}
    end.

%% @doc Send an event for the message back to the sender's site.
-spec send_message_event(Msg, EventArgs, Context) -> ok | {error, term()} when
    Msg :: binary() | proplists:proplist(),
    EventArgs :: map(),
    Context :: z:context().
send_message_event(SentMsgId, EventArgs, Context) when is_binary(SentMsgId) ->
    case fetch_decrypt(SentMsgId, Context) of
        {ok, Msg} -> send_message_event(Msg, EventArgs, Context);
        {error, _} = Error -> Error
    end;
send_message_event(Msg, EventArgs, Context) ->
    ReplyUrl = proplists:get_value(reply_url, Msg),
    MessageId = case proplists:get_value(message_id, Msg) of
        undefined -> proplists:get_value(generated_id, Msg);
        MId -> MId
    end,
    Event = EventArgs#{
        <<"message_id">> => MessageId,
        <<"recipient">> => proplists:get_value(recipient, Msg)
    },
    z_pivot_rsc:insert_task_after(1, ?MODULE, task_send_message_event, undefined, [ReplyUrl, Event], Context).


%% @doc Test event, send to default handler site
send_test_event(Context) ->
    EventUrl = m_config:get_value(mod_secure_message, event_url, Context),
    Args = #{
        <<"event">> => <<"test">>
    },
    ContextAdmin = z_acl:logon(1, Context),
    Options = [
        {content_type, "application/json"}
    ],
    z_fetch:fetch_json(post, EventUrl, Args, Options, ContextAdmin).

%% @doc Generic event, send to default handler site
send_generic_event(EventArgs, Context) ->
    z_pivot_rsc:insert_task_after(1, ?MODULE, task_send_message_event, undefined, [undefined, EventArgs], Context).

task_send_message_event(undefined, Args, Context) ->
    case m_config:get_value(mod_secure_message, event_url, Context) of
        undefined ->
            ?LOG_INFO(#{
                in => zotonic_mod_secure_message,
                text => <<"No event url for message">>,
                result => error,
                reason => url,
                args => Args
            }),
            {error, url};
        EventUrl ->
            task_send_message_event(EventUrl, Args, Context)
    end;
task_send_message_event(EventUrl, Args, Context) ->
    ContextAdmin = z_acl:logon(1, Context),
    Options = [
        {content_type, "application/json"}
    ],
    case z_fetch:fetch_json(post, EventUrl, Args, Options, ContextAdmin) of
        {ok, _Result} ->
            ok;
        {error, Reason} ->
            ?LOG_ERROR(#{
                in => zotonic_mod_secure_message,
                text => <<"Unexpected error from secure message event">>,
                result => error,
                reason => Reason,
                event_url => EventUrl
            }),
            {delay, 1800}
    end.

fetch_by_key(Key, Signature, Context) ->
    case z_db:assoc_row("
            select *
            from secure_message
            where generated_id = $1
              and destruct > now()",
            [Key],
            Context)
    of
        undefined ->
            log_error(undefined, unknown_msg_key, Context),
            {error, notfound};
        Msg ->
            MsgId = proplists:get_value(id, Msg),
            SignKey = proplists:get_value(sign_key, Msg),
            case is_valid_signature(Key, SignKey, Signature, Context) of
                true ->
                    decrypt_row(Msg, Context);
                false ->
                    log_error(MsgId, signature_error, Context),
                    {error, signature}
            end
    end.

%% @doc Fetch a record and decrypt its contents
fetch_decrypt(SentMsgId, Context) when is_binary(SentMsgId) ->
    case z_db:assoc_row("
        select *
        from secure_message
        where sent_message_id = $1",
        [SentMsgId],
        Context)
    of
        undefined -> {error, notfound};
        Row -> decrypt_row(Row, Context)
    end;
fetch_decrypt(Id, Context) when is_integer(Id) ->
    case z_db:assoc_row("
        select *
        from secure_message
        where id = $1",
        [Id],
        Context)
    of
        undefined -> {error, notfound};
        Row -> decrypt_row(Row, Context)
    end.


%% @todo Add encryption methods
encrypt_payload(Data, _Props, _Context) ->
    {ok, {<<"term">>, undefined, term_to_binary(Data)}}.

%% @todo Add decryption methods
decrypt_row(Msg, Context) ->
    CryptoType = proplists:get_value(crypto_type, Msg),
    CryptoData = proplists:get_value(crypto_data, Msg),
    Data = proplists:get_value(data, Msg),
    case decrypt_payload(CryptoType, CryptoData, Data, Context) of
        {ok, Props} ->
            {ok, Props ++ Msg};
        {error, Reason} = Error ->
            Id = proplists:get_value(id, Msg),
            ?LOG_ERROR(#{
                in => zotonic_mod_secure_message,
                text => <<"Secure Message failed decrypt">>,
                result => error,
                reason => Reason,
                message_id => Id
            }),
            Error
    end.

decrypt_payload(<<"term">>, _, Data, _Context) ->
    try
        {ok, binary_to_term(Data)}
    catch
        _:_ -> {error, term_format}
    end.

-spec view_count(integer(), #context{}) -> integer().
view_count(MsgId, Context) ->
    z_db:q1("
        select count(*) 
        from secure_message_event
        where secure_message_id = $1
          and event = 'view'",
        [MsgId],
        Context).

-spec is_valid_signature(Key, SignKey, Signature, Context) -> boolean() when
    Key :: string() | binary(),
    SignKey :: string() | binary(),
    Signature :: string() | binary(),
    Context :: z:context().
is_valid_signature(Key, SignKey, Signature, Context) ->
    Bin = z_convert:to_binary(Signature),
    Bin == sign(Key, SignKey, Context).

-spec sign(Key, SignKey, Context) -> Signature when
    Key :: string() | binary(),
    SignKey :: string() | binary(),
    Context :: z:context(),
    Signature :: binary().
sign(Key, SignKey, Context) ->
    Secret = secret(Context),
    Data = iolist_to_binary([Key, SignKey, Secret]),
    Bin = z_convert:to_binary(base64:encode(crypto:hash(sha256, Data))),
    Bin1 = binary:replace(Bin, <<"/">>, <<"-">>, [global]),
    binary:replace(Bin1, <<"+">>, <<"_">>, [global]).

secret(Context) ->
    case z_convert:to_binary(m_config:get_value(mod_secure_message, sign_key_secret, Context)) of
        <<>> ->
            Secret = z_ids:id(),
            m_config:set_value(mod_secure_message, sign_key_secret, Secret, Context),
            Secret;
        Secret ->
            Secret
    end.

update_view_dates(Msg, Context) ->
    MsgId = proplists:get_value(id, Msg),
    NewDestruct = next_week(),
    CurrDestruct = proplists:get_value(destruct, Msg),
    CurrOpened = proplists:get_value(opened, Msg),
    case CurrOpened of
        undefined when CurrDestruct > NewDestruct ->
            1 = z_db:q("
                    update secure_message
                    set opened = now(),
                        destruct = $1
                    where id = $2",
                    [NewDestruct, MsgId],
                    Context),
            ok;
        _ when CurrDestruct > NewDestruct ->
            1 = z_db:q("
                    update secure_message
                    set destruct = $1
                    where id = $2",
                    [NewDestruct, MsgId],
                    Context),
            ok;
        undefined ->
            1 = z_db:q("
                    update secure_message
                    set opened = now()
                    where id = $1",
                    [MsgId],
                    Context),
            ok;
        _ ->
            ok
    end.


log_access(MsgId, Context) ->
    UserAgent = sanitize(m_req:get(user_agent, Context)),
    Peer = ip2string(m_req:get(peer, Context)),
    maybe_log_db_event(MsgId, <<"view">>, <<>>, UserAgent, Peer, Context).


log_error(OptMsgId, Error, Context) ->
    UserAgent = sanitize(m_req:get(user_agent, Context)),
    Peer = ip2string(m_req:get(peer, Context)),
    ?LOG_WARNING(#{
        in => zotonic_mod_secure_message,
        text => <<"secure_message error">>,
        result => error,
        reason => Error,
        message_id => OptMsgId,
        user_agent => UserAgent,
        peer_ip => Peer
    }),
    maybe_log_db_event(OptMsgId, Error, <<>>, UserAgent, Peer, Context).

maybe_log_db_event(undefined, _Error, _Extra, _UserAgent, _Peer, _Context) ->
    {ok, undefined};
maybe_log_db_event(MsgId, Error, Extra, UserAgent, Peer, Context) ->
    z_db:insert(
        secure_message_event,
        [
            {secure_message_id, MsgId},
            {event, z_convert:to_binary(Error)},
            {extra, z_convert:to_binary(Extra)},
            {ip, Peer},
            {user_agent, UserAgent}
        ],
        Context).

sanitize(undefined) ->
    <<>>;
sanitize(S) ->
    L = z_convert:to_list(S),
    L1 = lists:filter(
        fun(C) ->
            C >= 32 andalso C < 127
        end,
        L),
    iolist_to_binary(L1).

ip2string(undefined) -> <<>>;
ip2string(Peer) when is_list(Peer) -> iolist_to_binary(Peer);
ip2string(Peer) when is_binary(Peer) -> Peer;
ip2string(Peer) -> iolist_to_binary(inet:ntoa(Peer)).

next_week() ->
    next_day(calendar:universal_time(), 7).

next_day(Date, 0) -> Date;
next_day(Date, N) -> next_day(z_datetime:next_day(Date), N-1).

prev_week() ->
    prev_day(calendar:universal_time(), 7).

prev_day(Date, 0) -> Date;
prev_day(Date, N) -> prev_day(z_datetime:prev_day(Date), N-1).


install(Context) ->
    % In data blob (optional encrypted):
    %
    % reply_url character varying(256),
    % subject text not null,
    % message text not null,
    % sender character varying(64),
    % recipient character varying(64),

    case z_db:table_exists(secure_message, Context) of
        false ->
            [] = z_db:q("
                create table secure_message (
                    id bigserial not null,
                    generated_id character varying(64),
                    sign_key character varying(64),
                    is_sent_error bool not null default false,
                    sent_message_id character varying (64),
                    language character varying (10) not null default 'en',
                    crypto_type character varying (32) not null,
                    crypto_data bytea,
                    data bytea,
                    created timestamp with time zone not null default current_timestamp, 
                    destruct timestamp with time zone not null,
                    opened timestamp with time zone,
                    sent timestamp with time zone,

                    constraint secure_message_pkey primary key (id),
                    constraint secure_message_external_id_key unique (generated_id)
                )",
                Context),
            [] = z_db:q("
                    create index secure_message_created_key on secure_message (created)
                ", Context),
            [] = z_db:q("
                    create index secure_message_destruct_key on secure_message (destruct)
                ", Context),
            [] = z_db:q("
                    create index secure_message_sent_message_id_key on secure_message (sent_message_id)
                ", Context),

            [] = z_db:q("
                create table secure_message_event (
                    id bigserial not null,
                    secure_message_id bigint not null,
                    event character varying (64) not null,
                    extra text,
                    ip character varying(128),
                    user_agent text,
                    created timestamp with time zone not null default current_timestamp,

                    constraint secure_message_event_pkey primary key (id),
                    constraint fk_secure_message_event_secure_message_id
                        foreign key (secure_message_id)
                        references secure_message (id)
                        on delete cascade
                        on update cascade
                )",
                Context),
            [] = z_db:q("
                    create index fki_secure_message_event_secure_message_id
                    on secure_message_event (secure_message_id)
                ", Context),
            ok;
        true ->
            ok
    end.

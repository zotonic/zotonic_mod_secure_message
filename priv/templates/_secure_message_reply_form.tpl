
{% wire id=#form
        type="submit"
        postback={secure_reply key=key signature=signature}
        delegate=`mod_secure_message`
%}
<form id="{{ #form }}" class="form form-horizontal" action="postback" method="POST">

    <div class="form-group row">
        <label class="col-md-2">
            {% if key %}
                {_ Reply _}
            {% else %}
                {_ Message _}
            {% endif %}
        </label>
        <div class="col-md-10">
            <textarea class="form-control" id="{{ #reply }}" name="reply" rows="5"></textarea>
            {% validate id=#reply name="reply" type={presence} %}
            {% if key %}
                <p class="help-block small">{_ Your reply will be forwarded to _} {{ sender|escape }}.</p>
            {% endif %}
        </div>
    </div>

    {% if not key %}
        <div class="form-group row">
            <label class="col-md-2">{_ First name _}</label>
            <div class="col-md-10">
                <input class="form-control" id="{{ #name_first }}" name="name_first" value="" />
                {% validate id=#name_first name="name_first" type={presence} %}
                <p class="help-block small">
                    {_ Nickname, or name you want us to call you. _}
                </p>
            </div>
        </div>
        <div class="form-group row">
            <label class="col-md-2">{_ Email _}</label>
            <div class="col-md-10">
                <input class="form-control" id="{{ #email }}" name="email" value="" />
                {% validate id=#email name="email" type={presence} type={email} %}
                <p class="help-block small">{_ On a reply, you will receive a link to this site. _}</p>
            </div>
        </div>
        <div class="form-group row">
            <label class="col-md-2">{_ Country _}</label>
            <div class="col-md-10">
                <select class="form-control" id="{{ #address_country }}" name="address_country">
                    <option></option>
                    <option value="us">United States</option>
                    <option disabled></option>
                    {% include "_l10n_country_options.tpl" %}
                </select>
                {% validate id=#address_country name="address_country" type={presence} %}
            </div>
        </div>

        <div class="form-group row">
            <label class="col-md-2">{_ State _}</label>
            <div class="col-md-10">
                <select class="form-control"  id="{{ #address_state }}" name="address_state">
                    <option></option>
                    {% include "_address_state_usa_options.tpl" %}
                </select>
                {#
                    {% validate id=#address_state name="address_state" type={presence} %}
                #}
            </div>
        </div>
    {% endif %}

    <div class="form-group row">
        <div class="col-md-offset-2 col-md-10">
            {% if key %}
                <button type="submit" class="btn btn-primary" name="msg">{_ Send Reply _}</button>
                <button type="submit" class="btn btn-success" name="msg-delete">{_ Send &amp; Delete Message _}</button>
            {% else %}
                <button type="submit" class="btn btn-primary" name="msg">{_ Send Message _}</button>
            {% endif %}
        </div>
    </div>
</form>

<div style="display: none" id="reply-sent">
    <p class="alert alert-info">
        <b>{_ Thank you. _}</b>
        {_ Your message has been sent, we will contact you as soon as possible. _}
    </p>
</div>


{% extends "base.tpl" %}

{% block html_head_extra %}
    {% inherit %}
    {% lib "css/secure-message.css" %}
{% endblock %}

{% block main %}
<h1>{_ Secure message _}</h1>

{% if q.key and q.signature %}
    {% if m.secure_message.qlookup as msg %}
        <br/>
        <p>{_ You received a message: _}<p>

        <div id="secure-message" class="secure-message">
            <p class="secure-message-header">
                <span class="text-muted">{_ From _}:</span> <b>{{ msg.sender|escape }}</b><br/>
                <span class="text-muted">{_ Date _}:</span> {{ msg.created|date:"Y-m-d H:i" }}<br/>
                <span class="text-muted">{_ Subject _}:</span> {{ msg.subject|escape }}
            </p>

            <div class="secure-message-body">
                {{ msg.message|sanitize_html }}
            </div>

            <p class="text-muted small">
                {% if msg.view_count > 1 %}
                    {{ msg.view_count }}x {_ viewed since _} {{ msg.opened|timesince:now:_"ago":1 }}.
                {% else %}
                    {_ First view. _}
                {% endif %}
                {_ This message will be deleted in _} {{ msg.destruct|timesince:now:"" }}.
                <a href="#" id="{{ #deletenow }}">{_ delete now _}</a>
                {% wire id=#deletenow
                        postback={secure_delete key=q.key signature=q.signature}
                        delegate=`mod_secure_message`
                %}
            </p>
        </div>

        {% if msg.reply_url %}
            {% include "_secure_message_reply_form.tpl" sender=msg.sender key=q.key signature=q.signature %}
        {% else %}
            <p class="text-muted">{_ You can’t reply directly to this message. _}</p>
        {% endif %}

    {% else %}

        <p class="alert alert-info">
            <b>{_ Not Found _}</b>
            {_ Either the link you tried is wrong or the message has been deleted. _}
        </p>

        {% include "_secure_message_reply_form.tpl" %}

    {% endif %}
{% else %}
    {% if q.deleted %}
        <p class="alert alert-info">
            <b>{_ Deleted _}</b>
            {_ Your message has been deleted. _}
        </p>
    {% endif %}

    {% include "_secure_message_reply_form.tpl" %}
{% endif %}

{% endblock %}


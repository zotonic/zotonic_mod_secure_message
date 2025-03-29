{% extends "email_base.tpl" %}

{% block title %}{_ Hello from _} {{ m.site.title }}{% endblock %}

{% block content %}

<div style="max-width: 600px; text-align: left; margin: 10px auto; padding:10px; border: 1px solid #ccc;">
    <p>{_ Hi, _}<br/>
    <br/>
    {_ You recently sent a question to our service. _}
    {_ To protect your privacy, we have answered your question at a safe place for you to read. _}<br/>
    <br/>
    {_ Please go to the link below for the information that you requested. _}<br/>
    <br/>
    <a href="{{ url }}">{{ url }}</a><br/>
    <br/>
    {_ For your security, our message will be deleted in 7 days. Please check the link above as soon as possible. _}<br/>
    <br/>
    {_ Thanks. _}<br/>
    </p>

    <p><br/></p>
</div>

<p style="color: #ccc;">
    {_ You can not reply to this email. Please reply at the link in the message. _}<br/>
    {_ Your email address will be automatically removed from our messaging service. _}
</p>

{% endblock %}

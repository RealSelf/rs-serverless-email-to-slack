# serverless-email-to-slack
A Serverless project that takes incoming HTML email and emits messages to slack.

It makes some expectations around the format of the incoming email: it expects that
the email will contain a `<table>`. 

If you're a user of splunk, and you wanted to schedule reports ( which you can send to email, but not slack ), this lambda could help.

It might work for any email that has a `<table>`

The SES -> SNS configuration is left as an exercise for the user.

# Secrets
This lambda needs (credstash)[https://github.com/fugue/credstash] to manage secrets.
Credstash requires the pycrypto python library. 
Pycrypto library includes a compiled module.
It's included here for your use as an example of how to do this.

This requirement also makes some other local dev funkiness, i.e. you need to do something like `pip install -t local_vendored/ pycrypto`


The secret is the SLACK_WEBHOOK. 
If you don't want the overhead mentioned above, you could pass it in as an environment variable on the lambda. You'd need to make some minor modification to handler.py to handle that

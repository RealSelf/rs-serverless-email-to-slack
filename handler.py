from __future__ import print_function
# load vendored directory
import sys
import os
here = os.path.dirname(os.path.realpath(__file__))
# local_vendored is for a local install of pycrypto
sys.path.append(os.path.join(here, "./local_vendored"))
# download_vendored is for a pycrypto from
# https://github.com/Doerge/awslambda-pycrypto
sys.path.append(os.path.join(here, "./download_vendored"))
sys.path.append(os.path.join(here, "./vendored"))

# regular include stuff
import json
import boto3
import email
import requests
import re
from datetime import datetime
from bs4 import BeautifulSoup
from base64 import b64encode, b64decode
#
import credstash
credstash.DEFAULT_REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')


def print_with_timestamp(*args):
    """
       Default printer is print
    """
    print(datetime.utcnow().isoformat(), *args)


def get_digest(digest):
    for item in globals().values():
        if (type(item) == ModuleType) and (item.__name__ == 'Crypto.Hash.' + digest):
            return item
    raise ValueError("Could not find " + digest + " in Crypto.Hash")


class KmsError(Exception):

    def __init__(self, value=""):
        self.value = "KMS ERROR: " + value if value is not "" else "KMS ERROR"

    def __str__(self):
        return self.value


class IntegrityError(Exception):

    def __init__(self, value=""):
        self.value = "INTEGRITY ERROR: " + value if value is not "" else \
                     "INTEGRITY ERROR"

    def __str__(self):
        return self.value


class ParseHtml(object):

    """
       Make a html parser, and give us just the facts for our needs
       title, and a dataframe ( optionally contains headers )
    """

    def __init__(self, html=None):
        self.soup = BeautifulSoup(html, 'html.parser')
        # Splunk formats with tables
        self.tables = self.soup.find_all('table')

    def give_title(self):
        for link in self.tables[0].find_all('a'):
            # There's just one link in the first table
            return (link.text, link.get('href'))

    def give_data(self, headers=False):
        # Returns an array of arrays. A bit wierd but trust me on this one
        retarrays = []
        for row in self.tables[1].find_all('tr'):
            if headers:
                retarrays.append([th.text for th in row.find_all('th')])
            retarrays.append([td.text for td in row.find_all('td')])
        # beautifulsoup isn't really to blame. there's td/tr s with
        # no text. so we strip those out.
        realretarrays = [x for x in retarrays if x]
        return realretarrays


def parse_email_recipients(to_address=None):
    #
    # if there is a plus sign, return whatever's between the plus sign and the @
    #   i.e. someemail+thisslackroom@your.com
    #
    return_address = re.findall('\+(.*)@', to_address)
    # 
    # nothing between the at. try this address
    #   i.e. thisslackroom@your.com
    # 
    if len(return_address) == 0:
        return_address = re.findall('^(.*)@', to_address)

    # lol idk wtf
    if len(return_address) == 0:
        return None
    return return_address[0]


def justify(listoflists=[]):
    if not isinstance(listoflists, list):
        raise Exception('justify needs a list of lists')
    numberoffields = len(listoflists[0])
    longestfield = {}
    for idx, l in enumerate(listoflists):
        if not isinstance(l, list):
            raise Exception('justify needs a list of lists')
        if len(l) != numberoffields:
            raise Exception('the %s list in the list of lists (%s) was not of the correct length(%s).' % (
                idx, l, numberoffields))
        for pos, item in enumerate(l):
            if longestfield.get(pos, 0) < len(str(item)):
                longestfield[pos] = len(str(item))
    returnlist = []
    for alist in listoflists:
        thisretlist = []
        for idx, thing in enumerate(alist):
            if len(str(thing)) < longestfield.get(idx):
                delta = longestfield.get(idx) - len(str(thing))
                thisretlist.append(' ' * delta + str(thing))
            else:
                thisretlist.append(thing)
        returnlist.append(thisretlist)
    return returnlist


def sns_parser(event, context):
    """
      event is the SNS event
      context is whatever it is
    """
    print_with_timestamp('Starting - SNS Triggered lambda')
    #print_with_timestamp('Event was {0}'.format(base64.b64encode(json.dumps(event))))
    #print_with_timestamp('Context was {0}'.format(base64.b64encode(json.dumps(context))))

    # ses_notification = event['Records'][0]['ses']
    # message_id = ses_notification['mail']['messageId']
    # receipt = ses_notification['receipt']
    try:
        message = json.loads(event['Records'][0]['Sns']['Message'])
        content = message['content']
        #print_with_timestamp('Message became ', json.dumps(message))
        #print_with_timestamp('Content became ', json.dumps(content))
    except:
        message = event['Records'][0]['Sns']['Message']
        # print_with_timestamp('Message became ', message)
        # print_with_timestamp('Content became ', content)
    # make an email.parser out of the content of the message ( hopefully it's
    # multipart )
    try:
        parsed_message = email.message_from_string(content)
    except:
        print_with_timestamp(
            "Failed to parse the content of the message: %s" % (content))
        return False
    #
    #print_with_timestamp("PARSED MESSAGE  ", json.dumps(parsed_message))

    # retain the html rendering of the message
    email_table = None
    # splunk default is to send multipart mails
    if parsed_message.is_multipart():
        for part in parsed_message.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))
            # print_with_timestamp("CTYPE: %s, CDISPO:%s, DIR:%s" % (ctype,
            # cdispo, part.get_payload(decode=True)))
            if ctype == 'text/html':
                email_table = part.get_payload(decode=True)
    else:
        print_with_timestamp("message was not multipart")
    if email_table:
        bsp = ParseHtml(email_table)
        ##print_with_timestamp("BSP Title   -=-=-  ", bsp.give_title())
        ##print_with_timestamp("BSP Headers -=-=-  ",
        ##                     bsp.give_data(headers=True))
        ##print_with_timestamp("BSP Data    -=-=-  ", bsp.give_data())

    slackmsg = {}
    slackmsg['attachments'] = [
        {"fallback": "Need a better fallback message",
            "color": "#000000",
            "author_name": "Splunk Search Results",
            "author_link": bsp.give_title()[1],
            "author_icon": "https://emoji.slack-edge.com/T0291FNNB/fine_scream/5fb7dcbafa3a008f.png",
            "title": bsp.give_title()[0],
            "title_link": bsp.give_title()[1],
            "text": "",
            "fields": [
                {
                    "title": "splunk results",
                    # a little gross, but justify() will rjustify text in a list
                    #   of lists
                    "value": '''```{0}```'''.format('\n'.join(' '.join(row) for row in justify(bsp.give_data(headers=True)))),
                    "short": False
                }
            ],
            "thumb_url": "https://emoji.slack-edge.com/T0291FNNB/splunk_logo/04f0d1af9a38910d.png",
            "footer": "Splunk lel",
            #"footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
            # when we want to use a timestamp "ts": 123456789,
            "mrkdwn_in": ["fields"]
         }
    ]

    # As far as I can tell, message['receipt']['recipients'][0] is the
    #    address that delivered to this lambda, and only that address
    slack_room_from_email_recip = parse_email_recipients(
        to_address=message['receipt']['recipients'][0])
    if slack_room_from_email_recip:
        slackmsg['channel'] = '#{0}'.format(slack_room_from_email_recip)

    # Creds now kept via credstash
    url_decrypted = credstash.getSecret(
        "{0}.SLACK_WEBHOOK_URL".format(context.function_name))
    try:
        r = requests.post(url_decrypted, json=slackmsg, allow_redirects=False)
        print_with_timestamp('Resp was ')
        print_with_timestamp(r)
    except Exception as e:
        print_with_timestamp("got exception")
        print_with_timestamp(e)

    # we'll get a 302 if the webook points to some 404 location
    if r.status_code == 302:
        raise Exception(
            'The url: {0} appeared invalid. Got back a 302 from slack.'.format(url_decrypted))

    # we get 404 on a valid webook url, and an invalid channel
    if r.status_code == 404:
        print_with_timestamp(
            "It looks like we were pointed to the channel: {0}, but that did not exist. Falling back to base webhook config".format(slackmsg['channel']))
        slackmsg.pop('channel', None)
        try:
            r = requests.post(url_decrypted, json=slackmsg,
                              allow_redirects=False)
            print_with_timestamp(
                'second response ( with no channel def ) was ')
            print_with_timestamp(r)
        except Exception as e:
            print_with_timestamp("got exception on fallback room. :sadpanda:")
            print_with_timestamp(e)

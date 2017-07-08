# inspiro_bot.py

import boto3
import httplib
import json
import logging
import os
import time
import decimal
from base64 import b64decode
from urlparse import parse_qs, urlparse


# decrypting the key passed thru the gateway from slack
encrypted_slackKey = os.environ['slackKey']
expected_token = boto3.client('kms').decrypt(CiphertextBlob=b64decode(encrypted_slackKey))['Plaintext']


# setup logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


# Is the last run less than 60 seconds ago?  True less than 60, false updated and
def get_dynamo_last_run(requesting_channel):
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
    current_epoch = int(time.time())
    table = dynamodb.Table('inspirobot')
    response = table.get_item(Key={"channel": requesting_channel})

    if 'Item' not in response:
        response = table.put_item(
            Item={
                'channel': requesting_channel,
                'lastRun': current_epoch
            }
        )
        return False

    last_run = response['Item']['lastRun']

    if last_run > (current_epoch - 60):
        return True
    else:
        response = table.update_item(
            Key={
                'channel': requesting_channel
            },
            UpdateExpression="set lastRun = :e",
            ExpressionAttributeValues={
                ':e': decimal.Decimal(current_epoch)
            },
            ReturnValues="UPDATED_NEW"
        )
        return False


# Immediate Responder to the users request - not visible to all
def respond(err, res=None):
    return {
        'statusCode': '400' if err else '200',
        'body': err.message if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }


# defining the function that will call inspirobot.me
def get_inspiration():
    headers = {'cache-control': 'no-cache'}
    conn = httplib.HTTPConnection("inspirobot.me")
    conn.request("GET", "/api?generate=true", headers=headers)
    response = conn.getresponse()
    inspiration_response = response.read()
    return inspiration_response


#  Post inspiration to Slack
def post_to_slack(user_name, conversation_url):
    inspiration_link = get_inspiration()
    payload = ("{\n\"response_type\": \"in_channel\",\n"
               "\"attachments\": [\n{\n\"author_name\": \"%s\",\n"
               "\"text\":\"Needed a little inspiration from /inspirobot\",\n"
               "\"image_url\":\"%s\"\n        }\n    ]\n}"
               % (user_name, inspiration_link))
    headers = {
        'content-type': "application/json",
        'cache-control': "no-cache"
    }
    parsed_url = urlparse(conversation_url)
    conn = httplib.HTTPSConnection(parsed_url.netloc)
    conn.request("POST", parsed_url.path, payload, headers)
    response = conn.getresponse()

    logger.info(response.status)
    logger.info(response.reason)


# defining the function that will handle the incoming slack request
def incoming_lambda_handler(event, context):
    params = parse_qs(event['body'])
    token = params['token'][0]
    if token != expected_token:
        logger.error("Request token (%s) does not match expected", token)
        return respond(Exception('Invalid request token'))

    user = params['user_name'][0]
    channel = params['channel_name'][0]
    conversation_url = params['response_url'][0]

    last_run = get_dynamo_last_run(channel)
    if last_run == True:
        return respond(None, ("Too soon /inspirobot has a 60s cool down"))

    if last_run == False:
        post_to_slack(user, conversation_url)
        return respond(None, ('inspirobot.me'))
    else:
        return respond(None, ("Hey - %s Pssstttt you are in the wrong channel or something went wrong" % user))

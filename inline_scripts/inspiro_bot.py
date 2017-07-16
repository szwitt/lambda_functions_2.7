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
logger.setLevel(logging.INFO)


# Is the last run less than 60 seconds ago?  True less than 60, false updated and
def dynamo_get_last_run(user_channel_id, user, channel):
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
    table = dynamodb.Table('inspirobot')
    current_epoch = int(time.time())
    ttl_epoch = (int(time.time() + 604800))
    response = table.get_item(Key={"user_channel_id": user_channel_id})
    if 'Item' not in response:
        table.put_item(
            Item={
                'user_channel_id': user_channel_id,
                'user': user,
                'channel': channel,
                'lastRun': current_epoch,
                'endRun': current_epoch,
                'expireTTL': ttl_epoch,
                'state': 'start',
                'inspirobot_count': 1,
                'shuffleCount': 0
            }
        )
        return False

    last_run = response['Item']['lastRun']
    new_count = (int(response['Item']['inspirobot_count']) + 1)
    logger.info(new_count)

    if last_run > (current_epoch - 1):  # Amount of time for request cool down
        return True
    else:
        table.update_item(
            Key={
                'user_channel_id': user_channel_id
            },
            UpdateExpression="set lastRun = :e, inspirobot_count = :c",
            ExpressionAttributeValues={
                ':e': decimal.Decimal(current_epoch),
                ':c': decimal.Decimal(new_count)
            },
            ReturnValues="UPDATED_NEW"
        )
        return False


# Update the inspiration link in the dyanmodb object.
def dynamo_update_inspiration(inspiration_link, user_channel_id):
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
    table = dynamodb.Table('inspirobot')
    table.update_item(
        Key={
            'user_channel_id': user_channel_id
        },
        UpdateExpression="set inspiration_url = :i",
        ExpressionAttributeValues={
            ':i': inspiration_link
        },
        ReturnValues="UPDATED_NEW"
    )
    return


# Immediate Responder to the users request - not visible to all
def respond(): #err, res=None
    return {
               'statusCode': '200'
#        'statusCode': '400' if err else '200',
#        'body': err.message if err else json.dumps(res),
#        'headers': {
#            'Content-Type': 'application/json',
#        },
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
def post_to_slack(user_name, conversation_url, user_channel_id):
    inspiration_link = get_inspiration()
    dynamo_update_inspiration(inspiration_link, user_channel_id)
    payload = ("{\n\"attachments\":"
               "[\n{\n\"fallback\":\"Inspiration for inspirobot.me\","
               "\n\"callback_id\":\"inspirobot_button\",\n\"attachment_type\":\"default\","
               "\n\"image_url\":\"%s\",\n\"text\":\"Inspiration hidden: hit publish to show the channel.\",\n\"actions\":"
               "[\n{\n\"name\":\"inspirobot\",\n\"text\":\"Publish\",\n\"type\":\"button\","
               "\n\"value\":\"publish\"\n},\n{\n\"name\":\"inspirobot\",\n\"text\":\"Shuffle\","
               "\n\"type\":\"button\",\n\"value\":\"shuffle\"\n},\n{\n\"name\":\"inspirobot\","
               "\n\"text\":\"Cancel\",\n\"type\":\"button\",\n\"style\":\"danger\","
               "\n\"value\":\"cancel\"\n}\n]\n}\n]\n}"
               % (inspiration_link))
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
    user_id = params['user_id'][0]
    channel = params['channel_name'][0]
    channel_id = params['channel_id'][0]
    conversation_url = params['response_url'][0]
    user_channel_id = ("%s-%s" % (user_id, channel_id))
    logger.info(user_channel_id)

    last_run = dynamo_get_last_run(user_channel_id, user, channel)


    if last_run == True:
        return respond() #(None, ("Too soon /inspirobot has a 60s cool down"))


    if last_run == False:
        post_to_slack(user, conversation_url, user_channel_id)
        return respond()
#        return respond(None, ('inspirobot.me'))
#    else:
#        return respond(None, ("Hey - %s Pssstttt you are in the wrong channel or something went wrong" % user))

# inspiro_bot_action.py

import boto3
import httplib
import logging
import json
import os
from base64 import b64decode
from urlparse import parse_qs, urlparse


# decrypting the key passed thru the gateway from slack
encrypted_slackKey = os.environ['slackKey']
expected_token = boto3.client('kms').decrypt(CiphertextBlob=b64decode(encrypted_slackKey))['Plaintext']


# setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Immediate Responder to the users request - not visible to all
def respond():
    return {
        'statusCode': '200'
#        'body': err.message if err else json.dumps(res),
#        'headers': {
#           'Content-Type': 'application/json',
#        },
    }

# Is the last run less than 60 seconds ago?  True less than 60, false updated and
def dynamo_get_record(user_channel_id):
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
    table = dynamodb.Table('inspirobot')
    response = table.get_item(Key={"user_channel_id": user_channel_id})

    if 'Item' in response:
        inspiration_from_db = response['Item']['inspiration_url']
        return inspiration_from_db


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



# defining the function that will call inspirobot.me
def get_inspiration():
    headers = {'cache-control': 'no-cache'}
    conn = httplib.HTTPConnection("inspirobot.me")
    conn.request("GET", "/api?generate=true", headers=headers)
    response = conn.getresponse()
    inspiration_response = response.read()
    return inspiration_response


#  Shuffle inspiration message in slack
def shuffle_slack_message(user_name, conversation_url, user_channel_id):
    inspiration_link = get_inspiration()
    dynamo_update_inspiration(inspiration_link, user_channel_id)
    payload = ("{\n\"attachments\":"
               "[\n{\n\"fallback\":\"Inspiration from inspirobot.me\","
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

#  Shuffle inspiration message in slack
def publish_slack_message(user_name, conversation_url, user_channel_id):
    inspiration_link = dynamo_get_record(user_channel_id)
    logger.info(inspiration_link)
    payload = ("{\n\"delete_original\":\"true\","
               "\n\"response_type\":\"in_channel\",\n\"attachments\":" \
               "[\n{\n\"fallback\":\"Inspiration from inspirobot.me\"," \
               "\n\"callback_id\":\"inspirobot_button\",\n\"attachment_type\":\"default\"," \
               "\n\"image_url\":\"%s\",\n\"text\":\"inspirobot.me from %s\"\n}\n]\n}"
               % (inspiration_link, user_name))
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


#  Post inspiration to Slack
def delete_slack_message(conversation_url):
    payload = "{\n\"delete_original\": True\n}"
    headers = {
        'content-type': "application/json",
        'cache-control': "no-cache"
    }
    logger.info(payload)
    parsed_url = urlparse(conversation_url)
    conn = httplib.HTTPSConnection(parsed_url.netloc)
    conn.request("POST", parsed_url.path, payload, headers)
    response = conn.getresponse()

    logger.info(response.status)
    logger.info(response.reason)

# defining the function that will handle the incoming slack request
def incoming_lambda_handler(event, context):
    params = parse_qs(event['body'])

    payload = params['payload'][0]
    payload_params = json.loads(payload)
    token = payload_params['token']
    if token != expected_token:
        logger.error("Request token (%s) does not match expected", token)
        logger.error(payload)
        return respond()

    button_select = payload_params['actions'][0]['value']
    channel_id = payload_params['channel']['id']
    conversation_url = payload_params['response_url']
    user = payload_params['user']['name']
    user_id = payload_params['user']['id']
    user_channel_id = ("%s-%s" % (user_id, channel_id))

    logger.info(payload)


    if button_select == "shuffle":
        shuffle_slack_message(user, conversation_url, user_channel_id)
        return respond()


    if button_select == "publish":
        publish_slack_message(user, conversation_url, user_channel_id)
        return respond()


    if  button_select == "cancel":
        delete_slack_message(conversation_url)
        return respond()
